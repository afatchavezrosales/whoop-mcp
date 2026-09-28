import { DurableObject } from "cloudflare:workers";
import { listActiveGrants, mcpUserIdFor } from "./grants";
import { revokeWhoopAccess } from "./whoop/api";
import { refreshWhoopTokens, whoopCredentials, WhoopTokenError, type WhoopTokens } from "./whoop/oauth";

// =============================================================================
// WhoopTokenVault — un Durable Object por usuario de WHOOP (idFromName(userId)).
//
// Guarda los tokens de WHOOP en el storage del DO (privado al objeto y cifrado
// en reposo por Cloudflare; ningún endpoint HTTP lo expone) y los refresca de
// forma SERIALIZADA: WHOOP rota el refresh token en cada uso, así que dos
// refrescos concurrentes con el mismo refresh token romperían la conexión. El
// DO es un único hilo lógico y además encadena los refrescos en `inFlight`
// (durante un fetch saliente el DO sí puede atender otras llamadas).
//
// Solo lo invoca el propio Worker por RPC; el nombre del objeto sale de las
// props cifradas del grant OAuth (o de un webhook firmado por WHOOP), nunca de
// la petición del cliente.
//
// Desconexión (disconnect): revoca el acceso en WHOOP (DELETE /v2/user/access)
// y borra TODO el storage del objeto. Además, una alarma comprueba de vez en
// cuando si al usuario le queda algún grant MCP vigente: si todos caducaron
// (el cliente dejó de usarlo y nadie llamó a revoke), se desconecta solo.
// =============================================================================

const TOKENS_KEY = "tokens";
const REVOKED_KEY = "revoked";
const USER_KEY = "whoop_user_id";
/** Margen de seguridad: se refresca si al token le quedan menos de 2 minutos. */
const EXPIRY_SKEW_MS = 120_000;
/** Primera comprobación de grants: poco después de la caducidad por inactividad (30 días). */
const GRANT_CHECK_AFTER_STORE_MS = 31 * 24 * 60 * 60 * 1000;
/** Holgura tras la caducidad del grant más longevo antes de volver a mirar. */
const GRANT_CHECK_MARGIN_MS = 60 * 60 * 1000;

export type VaultStatus = "connected" | "revoked" | "empty";

export interface DisconnectResult {
	/** Había tokens de WHOOP guardados. */
	hadTokens: boolean;
	/** WHOOP confirmó la revocación (204). */
	whoopAccessRevoked: boolean;
	/** Status de DELETE /v2/user/access (0 = error de red, null = no se llamó). */
	whoopStatus: number | null;
}

export class WhoopTokenVault extends DurableObject<Env> {
	private inFlight: Promise<string> | null = null;

	/** Guarda los tokens recién emitidos por WHOOP (callback OAuth). Pisa lo anterior. */
	async storeTokens(tokens: WhoopTokens, whoopUserId?: string): Promise<void> {
		await this.ctx.storage.put(TOKENS_KEY, tokens);
		await this.ctx.storage.delete(REVOKED_KEY);
		if (whoopUserId) await this.ctx.storage.put(USER_KEY, whoopUserId);
		await this.ctx.storage.setAlarm(Date.now() + GRANT_CHECK_AFTER_STORE_MS);
	}

	/**
	 * Revoca el acceso de la app en WHOOP con el token del usuario y borra todo
	 * lo guardado (tokens, estado, alarma). Idempotente. El borrado local ocurre
	 * SIEMPRE, aunque WHOOP falle: el usuario puede revocar también desde la app
	 * de WHOOP.
	 */
	async disconnect(): Promise<DisconnectResult> {
		const hadTokens = (await this.ctx.storage.get<WhoopTokens>(TOKENS_KEY)) !== undefined;
		let whoopStatus: number | null = null;
		if (hadTokens) {
			try {
				let token = await this.getAccessToken();
				whoopStatus = await revokeWhoopAccess(token);
				if (whoopStatus === 401) {
					token = await this.getAccessToken(token);
					whoopStatus = await revokeWhoopAccess(token);
				}
			} catch (error) {
				// Sin token utilizable (revocado en WHOOP, refresh muerto): no hay nada que revocar allí.
				console.warn("disconnect: no se pudo obtener un token de WHOOP:", error instanceof Error ? error.message : error);
			}
		}
		await this.ctx.storage.deleteAlarm();
		await this.ctx.storage.deleteAll();
		return { hadTokens, whoopAccessRevoked: whoopStatus === 204, whoopStatus };
	}

	/**
	 * Comprobación periódica: si el usuario ya no tiene ningún grant MCP vigente
	 * (caducaron por inactividad o se borraron sin pasar por revoke), desconecta.
	 * Si le quedan, reprograma la alarma para después del que más dure.
	 */
	override async alarm(): Promise<void> {
		const whoopUserId = await this.ctx.storage.get<string>(USER_KEY);
		const tokens = await this.ctx.storage.get<WhoopTokens>(TOKENS_KEY);
		if (!whoopUserId || !tokens) {
			await this.ctx.storage.deleteAll();
			return;
		}
		const grants = await listActiveGrants(this.env, mcpUserIdFor(whoopUserId));
		if (grants.length === 0) {
			const result = await this.disconnect();
			console.log("Sin grants MCP vigentes: WHOOP desconectado.", { whoopStatus: result.whoopStatus });
			return;
		}
		const expiries = grants.map((grant) => grant.expiresAt);
		const next = expiries.some((expiresAt) => expiresAt === undefined)
			? Date.now() + GRANT_CHECK_AFTER_STORE_MS
			: Math.max(...(expiries as number[])) * 1000 + GRANT_CHECK_MARGIN_MS;
		await this.ctx.storage.setAlarm(Math.max(next, Date.now() + GRANT_CHECK_MARGIN_MS));
	}

	async status(): Promise<VaultStatus> {
		if (await this.ctx.storage.get<boolean>(REVOKED_KEY)) return "revoked";
		return (await this.ctx.storage.get<WhoopTokens>(TOKENS_KEY)) ? "connected" : "empty";
	}

	/** Borra los tokens de WHOOP de este usuario. */
	async clear(): Promise<void> {
		await this.ctx.storage.delete(TOKENS_KEY);
	}

	/**
	 * Devuelve un access token válido, refrescándolo si caduca pronto.
	 * `rejectedToken`: el token que WHOOP acaba de rechazar con 401; fuerza el
	 * refresh salvo que otro caller ya lo haya rotado (entonces reutiliza el nuevo).
	 * Lanza un Error con prefijo "REAUTH:" si el usuario debe reconectar WHOOP.
	 */
	async getAccessToken(rejectedToken?: string): Promise<string> {
		// Todo refresh pasa por la misma promesa: nunca hay dos en vuelo.
		while (this.inFlight) {
			try {
				await this.inFlight;
			} catch {
				// El error ya lo recibió quien lanzó ese refresh; reevaluamos el estado.
			}
		}

		const tokens = await this.ctx.storage.get<WhoopTokens>(TOKENS_KEY);
		if (!tokens) {
			throw new Error(
				"REAUTH: No hay una cuenta de WHOOP conectada (o se revocó). Vuelve a conectar el servidor MCP de WHOOP.",
			);
		}

		const stillFresh = tokens.expiresAt - EXPIRY_SKEW_MS > Date.now();
		if (stillFresh && (!rejectedToken || rejectedToken !== tokens.accessToken)) {
			return tokens.accessToken;
		}

		this.inFlight = this.refresh(tokens);
		try {
			return await this.inFlight;
		} finally {
			this.inFlight = null;
		}
	}

	private async refresh(current: WhoopTokens): Promise<string> {
		const credentials = whoopCredentials(this.env);
		if (!credentials) {
			throw new Error(
				"Servidor WHOOP MCP sin configurar: faltan los secretos WHOOP_CLIENT_ID / WHOOP_CLIENT_SECRET.",
			);
		}
		if (!current.refreshToken) {
			await this.markRevoked();
			throw new Error(
				"REAUTH: WHOOP no emitió refresh token (falta el scope offline). Vuelve a conectar WHOOP.",
			);
		}

		try {
			const next = await refreshWhoopTokens({ ...credentials, refreshToken: current.refreshToken });
			// Persistir ANTES de devolver: el refresh token viejo ya está consumido.
			await this.ctx.storage.put(TOKENS_KEY, next);
			return next.accessToken;
		} catch (error) {
			if (error instanceof WhoopTokenError && error.permanent) {
				await this.markRevoked();
				throw new Error(
					"REAUTH: WHOOP ya no acepta la autorización (revocada o caducada). Vuelve a conectar WHOOP.",
				);
			}
			throw error;
		}
	}

	private async markRevoked(): Promise<void> {
		await this.ctx.storage.delete(TOKENS_KEY);
		await this.ctx.storage.put(REVOKED_KEY, true);
	}
}

/** Stub del vault de un usuario de WHOOP. */
export function vaultFor(env: Env, whoopUserId: string): DurableObjectStub<WhoopTokenVault> {
	const namespace = env.WHOOP_TOKEN_VAULT as DurableObjectNamespace<WhoopTokenVault>;
	return namespace.get(namespace.idFromName(`whoop-user:${whoopUserId}`));
}

/** Los errores que cruzan RPC pierden la clase: se distingue por prefijo. */
export function isReauthMessage(error: unknown): boolean {
	return error instanceof Error && error.message.startsWith("REAUTH:");
}
