import { getOAuthApi, type GrantSummary, type OAuthHelpers } from "@cloudflare/workers-oauth-provider";

// =============================================================================
// Grants MCP de un usuario de WHOOP (KV del OAuth provider).
//
// El userId de cada grant es `whoop-<user_id de WHOOP>` (ver auth-handler.ts):
// un usuario de WHOOP puede tener VARIOS grants (uno por cliente MCP) que
// comparten un único WhoopTokenVault. Estas utilidades las usan el Worker
// (revocación, desconexión) y el propio Durable Object (alarma de caducidad),
// que no tiene `env.OAUTH_PROVIDER`: por eso se construyen los helpers con
// getOAuthApi(). Listar y revocar grants solo depende del KV `OAUTH_KV`, no de
// los handlers ni del resto de opciones, que aquí son mínimas y válidas.
// =============================================================================

const MCP_USER_PREFIX = "whoop-";
const noop = { fetch: () => new Response(null, { status: 404 }) };

export function mcpUserIdFor(whoopUserId: string): string {
	return `${MCP_USER_PREFIX}${whoopUserId}`;
}

/** user_id de WHOOP a partir del userId del grant, o null si no es de este servidor. */
export function whoopUserIdFromMcpUserId(userId: string): string | null {
	if (!userId.startsWith(MCP_USER_PREFIX)) return null;
	const id = userId.slice(MCP_USER_PREFIX.length);
	return /^\d{1,20}$/.test(id) ? id : null;
}

export function oauthHelpers(env: Env): OAuthHelpers {
	const baseUrl = String(env.PUBLIC_BASE_URL).replace(/\/+$/, "");
	return getOAuthApi<Env>(
		{
			apiRoute: "/mcp",
			apiHandler: noop,
			defaultHandler: noop,
			authorizeEndpoint: "/authorize",
			tokenEndpoint: "/token",
			resourceMetadata: { resource: `${baseUrl}/mcp` },
		},
		env,
	);
}

/** Grants vigentes (no caducados) de un usuario MCP, recorriendo todas las páginas. */
export async function listActiveGrants(env: Env, userId: string): Promise<GrantSummary[]> {
	const helpers = oauthHelpers(env);
	const nowSeconds = Math.floor(Date.now() / 1000);
	const grants: GrantSummary[] = [];
	let cursor: string | undefined;
	do {
		const page = await helpers.listUserGrants(userId, cursor ? { cursor } : undefined);
		for (const grant of page.items) {
			if (grant.expiresAt === undefined || grant.expiresAt > nowSeconds) grants.push(grant);
		}
		cursor = page.cursor;
	} while (cursor);
	return grants;
}

/** Revoca todos los grants (y sus tokens) de un usuario MCP. Devuelve cuántos había. */
export async function revokeAllGrants(env: Env, userId: string): Promise<number> {
	const helpers = oauthHelpers(env);
	const ids: string[] = [];
	let cursor: string | undefined;
	do {
		const page = await helpers.listUserGrants(userId, cursor ? { cursor } : undefined);
		ids.push(...page.items.map((grant) => grant.id));
		cursor = page.cursor;
	} while (cursor);
	for (const id of ids) await helpers.revokeGrant(id, userId);
	return ids.length;
}
