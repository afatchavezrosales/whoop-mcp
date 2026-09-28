import { env as workerEnv } from "cloudflare:workers";
import OAuthProvider, {
	GrantType,
	OAuthError,
	insufficientScope,
	type OAuthResourceAuth,
	type TokenExchangeCallbackOptions,
} from "@cloudflare/workers-oauth-provider";
import { createMcpHandler, getMcpAuthContext } from "agents/mcp/server";
import { MCP_SCOPE, authHandler } from "./auth-handler";
import { listActiveGrants, mcpUserIdFor, revokeAllGrants, whoopUserIdFromMcpUserId } from "./grants";
import { createWhoopMcpServer } from "./mcp-server";
import { vaultFor } from "./token-vault";
import { handleWhoopWebhook, WHOOP_WEBHOOK_PATH } from "./webhooks";
import { createWhoopApi, type WhoopApi } from "./whoop/api";
import { whoopCredentials } from "./whoop/oauth";

export { WhoopTokenVault } from "./token-vault";

// =============================================================================
// whoop-mcp — servidor MCP REMOTO (Streamable HTTP, sin estado) de WHOOP,
// de solo lectura, protegido con OAuth 2.1 (@cloudflare/workers-oauth-provider).
//
//   Cliente MCP ──OAuth 2.1 + PKCE──▶ este Worker ──OAuth 2.0──▶ WHOOP
//
// El Worker es servidor de autorización para los clientes MCP (DCR en
// /register, CIMD, metadata RFC 8414/9728) y cliente OAuth de WHOOP aguas
// arriba. El token de WHOOP vive en un Durable Object por usuario
// (WhoopTokenVault), que lo refresca de forma serializada; el grant del
// cliente MCP solo lleva cifrado el whoopUserId.
//
// Rutas propias además de las del provider:
//   POST /webhooks/whoop     webhooks de WHOOP verificados → reenvío firmado
//   POST /mcp/disconnect     (Bearer) el usuario se desconecta de WHOOP
//   GET  /icon.svg           icono del servidor (serverInfo.icons)
// =============================================================================

const THIRTY_DAYS = 30 * 24 * 60 * 60;
const DISCONNECT_PATH = "/mcp/disconnect";

function currentWhoopUserId(): string {
	const whoopUserId = getMcpAuthContext()?.props?.whoopUserId;
	if (typeof whoopUserId !== "string" || whoopUserId.length === 0) {
		throw new Error("REAUTH: La sesión no identifica ninguna cuenta de WHOOP. Vuelve a conectar WHOOP.");
	}
	return whoopUserId;
}

/** Resuelve el cliente de WHOOP del usuario del token que hace la petición MCP. */
function resolveWhoopApi(): WhoopApi {
	if (!whoopCredentials(workerEnv)) {
		throw new Error(
			"Servidor WHOOP MCP sin configurar: faltan los secretos WHOOP_CLIENT_ID / WHOOP_CLIENT_SECRET del Worker.",
		);
	}
	const vault = vaultFor(workerEnv, currentWhoopUserId());
	return createWhoopApi({ getAccessToken: (rejectedToken) => vault.getAccessToken(rejectedToken) });
}

/**
 * Desconexión completa de un usuario de WHOOP: revoca el acceso de la app en
 * WHOOP (DELETE /v2/user/access), borra su token del vault y revoca TODOS sus
 * grants MCP (todos los clientes: sin acceso en WHOOP ninguno funcionaría).
 */
async function disconnectWhoopUser(
	env: Env,
	whoopUserId: string,
): Promise<{ whoopAccessRevoked: boolean; grantsRevoked: number }> {
	const vaultResult = await vaultFor(env, whoopUserId).disconnect();
	const grantsRevoked = await revokeAllGrants(env, mcpUserIdFor(whoopUserId));
	return { whoopAccessRevoked: vaultResult.whoopAccessRevoked, grantsRevoked };
}

const mcpHandler = createMcpHandler(
	() =>
		createWhoopMcpServer(resolveWhoopApi, () => disconnectWhoopUser(workerEnv, currentWhoopUserId()), {
			publicBaseUrl: workerEnv.PUBLIC_BASE_URL,
		}),
	{ route: "/mcp" },
);

async function handleDisconnectRoute(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	if (request.method !== "POST") {
		return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { Allow: "POST" } });
	}
	const whoopUserId = (ctx as ExecutionContext & { props?: { whoopUserId?: unknown } }).props?.whoopUserId;
	if (typeof whoopUserId !== "string" || whoopUserId.length === 0) {
		return Response.json({ error: "invalid_token" }, { status: 401 });
	}
	const result = await disconnectWhoopUser(env, whoopUserId);
	return Response.json(
		{ disconnected: true, whoop_access_revoked: result.whoopAccessRevoked, mcp_grants_revoked: result.grantsRevoked },
		{ headers: { "Cache-Control": "no-store" } },
	);
}

const apiHandler = {
	fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> | Response {
		const auth = (ctx as ExecutionContext & { auth?: OAuthResourceAuth }).auth;
		if (auth && !auth.scope.includes(MCP_SCOPE)) {
			return insufficientScope(auth, [MCP_SCOPE]);
		}
		if (new URL(request.url).pathname === DISCONNECT_PATH) return handleDisconnectRoute(request, env, ctx);
		return mcpHandler(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;

interface RevocationTarget {
	userId: string;
	grantId: string;
	whoopUserId: string;
}

/**
 * ¿Es una petición de revocación RFC 7009 (POST /token sin grant_type y con
 * `token`) de un token nuestro? Los tokens del provider son `userId:grantId:secreto`.
 * Solo se lee una copia del cuerpo: el provider procesa la original.
 */
async function revocationTarget(request: Request): Promise<RevocationTarget | null> {
	const contentType = (request.headers.get("Content-Type") ?? "").split(";")[0]!.trim().toLowerCase();
	if (request.method !== "POST" || contentType !== "application/x-www-form-urlencoded") return null;
	let form: FormData;
	try {
		form = await request.clone().formData();
	} catch {
		return null;
	}
	const token = form.get("token");
	if (form.has("grant_type") || typeof token !== "string") return null;
	const parts = token.split(":");
	if (parts.length !== 3) return null;
	const [userId, grantId] = parts as [string, string, string];
	const whoopUserId = whoopUserIdFromMcpUserId(userId);
	return whoopUserId && grantId ? { userId, grantId, whoopUserId } : null;
}

/**
 * Tras una revocación válida: revocar un refresh token borra el grant entero
 * (revocar un access token solo borra ese token y la conexión sigue). Si el
 * grant desapareció y el usuario no tiene otros grants vigentes (otros
 * clientes MCP), se revoca el acceso en WHOOP y se borra su token.
 */
async function afterRevocation(env: Env, target: RevocationTarget): Promise<void> {
	const remaining = await listActiveGrants(env, target.userId);
	if (remaining.some((grant) => grant.id === target.grantId)) return;
	if (remaining.length > 0) {
		console.log(`Grant revocado; el usuario mantiene ${remaining.length} grant(s) de otros clientes: WHOOP sigue conectado.`);
		return;
	}
	const result = await vaultFor(env, target.whoopUserId).disconnect();
	console.log("Último grant revocado: WHOOP desconectado.", { whoopStatus: result.whoopStatus });
}

async function handleTokenEndpoint(
	provider: OAuthProvider<Env>,
	request: Request,
	env: Env,
	ctx: ExecutionContext,
): Promise<Response> {
	const target = await revocationTarget(request);
	if (!target) return provider.fetch(request, env, ctx);
	let existed = false;
	try {
		existed = (await listActiveGrants(env, target.userId)).some((grant) => grant.id === target.grantId);
	} catch (error) {
		console.warn("No se pudo comprobar el grant antes de revocar:", error instanceof Error ? error.message : error);
	}
	const response = await provider.fetch(request, env, ctx);
	// Solo si el grant existía: un token inventado (RFC 7009 responde 200 igual) no desconecta a nadie.
	if (existed && response.ok) {
		ctx.waitUntil(
			afterRevocation(env, target).catch((error) => {
				console.error("Fallo al desconectar WHOOP tras la revocación:", error instanceof Error ? error.message : error);
			}),
		);
	}
	return response;
}

/**
 * En cada refresh del token MCP: si el vault ya no tiene tokens de WHOOP
 * (revocados en WHOOP o refresh token muerto), se responde invalid_grant, lo que
 * revoca este grant y obliga al cliente a re-autorizar en vez de reintentar.
 */
async function tokenExchangeCallback(options: TokenExchangeCallbackOptions<Env>) {
	if (options.grantType !== GrantType.REFRESH_TOKEN) return;
	const whoopUserId = (options.props as { whoopUserId?: unknown } | undefined)?.whoopUserId;
	if (typeof whoopUserId !== "string") {
		throw new OAuthError("invalid_grant", { description: "El grant no identifica ninguna cuenta de WHOOP." });
	}
	let status: string;
	try {
		status = await vaultFor(options.env, whoopUserId).status();
	} catch {
		throw new OAuthError("temporarily_unavailable", {
			description: "No se pudo comprobar la conexión con WHOOP.",
			statusCode: 503,
		});
	}
	if (status !== "connected") {
		throw new OAuthError("invalid_grant", {
			description: "La autorización de WHOOP ya no es válida. Vuelve a conectar WHOOP.",
		});
	}
}

function createProvider(baseUrl: string): OAuthProvider<Env> {
	return new OAuthProvider<Env>({
		apiRoute: "/mcp",
		apiHandler,
		defaultHandler: authHandler as unknown as ExportedHandler<Env>,
		authorizeEndpoint: "/authorize",
		tokenEndpoint: "/token",
		clientRegistrationEndpoint: "/register",
		clientIdMetadataDocumentEnabled: true,
		scopesSupported: [MCP_SCOPE],
		requiredScopes: [MCP_SCOPE],
		resourceMetadata: {
			resource: `${baseUrl}/mcp`,
			authorization_servers: [baseUrl],
			resource_name: "WHOOP (solo lectura)",
		},
		accessTokenTTL: 3600,
		refreshTokenTTL: THIRTY_DAYS,
		// La conexión vive mientras se use (al menos una vez al mes).
		refreshTokenIdleTTL: THIRTY_DAYS,
		tokenExchangeCallback,
	});
}

let cached: { baseUrl: string; provider: OAuthProvider<Env> } | null = null;

function providerFor(env: Env): OAuthProvider<Env> {
	const baseUrl = String(env.PUBLIC_BASE_URL).replace(/\/+$/, "");
	if (!cached || cached.baseUrl !== baseUrl) {
		cached = { baseUrl, provider: createProvider(baseUrl) };
	}
	return cached.provider;
}

export default {
	fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const { pathname } = new URL(request.url);
		if (pathname === WHOOP_WEBHOOK_PATH) return handleWhoopWebhook(request, env, ctx);
		const provider = providerFor(env);
		if (pathname === "/token") return handleTokenEndpoint(provider, request, env, ctx);
		return provider.fetch(request, env, ctx);
	},
} satisfies ExportedHandler<Env>;
