// =============================================================================
// Cliente OAuth 2.0 de WHOOP (aguas arriba).
//
// Este Worker es cliente OAuth CONFIDENCIAL de WHOOP (client_id + client_secret
// como secretos del Worker). Endpoints y scopes según
// https://developer.whoop.com/docs/developing/oauth.
//
// Gotcha de WHOOP: los refresh tokens son de UN SOLO
// USO y rotan en cada refresh; el refresh DEBE volver a pedir `offline` en
// `scope` o WHOOP consume el refresh token viejo y no devuelve uno nuevo, con lo
// que el siguiente refresh muere con 400. Por eso el refresh se serializa en un
// Durable Object por usuario (ver token-vault.ts).
// =============================================================================

export const WHOOP_AUTHORIZE_URL = "https://api.prod.whoop.com/oauth/oauth2/auth";
export const WHOOP_TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token";

/** Scopes de SOLO LECTURA que usan las tools, más `offline` para el refresh token. */
export const WHOOP_SCOPES = [
	"offline",
	"read:profile",
	"read:body_measurement",
	"read:recovery",
	"read:cycles",
	"read:sleep",
	"read:workout",
] as const;

export const WHOOP_SCOPE_STRING = WHOOP_SCOPES.join(" ");

/** Ruta del callback de WHOOP en este Worker (la redirect URI a registrar en WHOOP). */
export const WHOOP_CALLBACK_PATH = "/callback";

const TOKEN_REQUEST_TIMEOUT_MS = 15_000;

export interface WhoopCredentials {
	clientId: string;
	clientSecret: string;
}

/** Tokens de WHOOP tal y como se persisten en el vault. `expiresAt` en ms epoch. */
export interface WhoopTokens {
	accessToken: string;
	refreshToken: string | null;
	expiresAt: number;
	scope: string;
}

/**
 * Error del endpoint de tokens de WHOOP. `permanent` = el grant ya no sirve
 * (revocado, refresh token consumido/caducado): hay que re-autorizar.
 */
export class WhoopTokenError extends Error {
	override readonly name = "WhoopTokenError";
	constructor(
		readonly status: number,
		readonly oauthError: string | null,
		readonly permanent: boolean,
		message: string,
	) {
		super(message);
	}
}

/** Devuelve las credenciales de la app de WHOOP, o null si faltan los secretos. */
export function whoopCredentials(env: {
	WHOOP_CLIENT_ID?: string;
	WHOOP_CLIENT_SECRET?: string;
}): WhoopCredentials | null {
	const clientId = env.WHOOP_CLIENT_ID?.trim();
	const clientSecret = env.WHOOP_CLIENT_SECRET?.trim();
	if (!clientId || !clientSecret) return null;
	return { clientId, clientSecret };
}

export function whoopRedirectUri(publicBaseUrl: string): string {
	return `${publicBaseUrl.replace(/\/+$/, "")}${WHOOP_CALLBACK_PATH}`;
}

export function buildWhoopAuthorizeUrl(params: {
	clientId: string;
	redirectUri: string;
	state: string;
	codeChallenge: string;
}): string {
	const url = new URL(WHOOP_AUTHORIZE_URL);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", params.clientId);
	url.searchParams.set("redirect_uri", params.redirectUri);
	url.searchParams.set("scope", WHOOP_SCOPE_STRING);
	url.searchParams.set("state", params.state);
	url.searchParams.set("code_challenge", params.codeChallenge);
	url.searchParams.set("code_challenge_method", "S256");
	return url.toString();
}

/** base64url(SHA-256(verifier)) — PKCE S256. */
export async function pkceChallenge(verifier: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
	return base64Url(new Uint8Array(digest));
}

/** 64 bytes aleatorios en base64url (86 chars, dentro del rango 43-128 de RFC 7636). */
export function generatePkceVerifier(): string {
	const bytes = new Uint8Array(64);
	crypto.getRandomValues(bytes);
	return base64Url(bytes);
}

function base64Url(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface RawTokenResponse {
	access_token?: unknown;
	refresh_token?: unknown;
	expires_in?: unknown;
	scope?: unknown;
}

async function postTokenEndpoint(
	body: URLSearchParams,
	fetchImpl: typeof fetch,
): Promise<RawTokenResponse> {
	let response: Response;
	try {
		response = await fetchImpl(WHOOP_TOKEN_URL, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
				Accept: "application/json",
			},
			body: body.toString(),
			signal: AbortSignal.timeout(TOKEN_REQUEST_TIMEOUT_MS),
		});
	} catch (error) {
		throw new WhoopTokenError(
			0,
			null,
			false,
			`No se pudo contactar con WHOOP (${error instanceof Error ? error.message : "error de red"}).`,
		);
	}

	const text = await response.text();
	let json: Record<string, unknown> = {};
	try {
		json = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {
		json = {};
	}

	if (!response.ok) {
		const oauthError = typeof json.error === "string" ? json.error : null;
		const description =
			typeof json.error_description === "string" ? json.error_description : response.statusText;
		// 400/401 con invalid_grant/invalid_request/unauthorized_client = el grant no volverá a
		// funcionar. 429/5xx = transitorio.
		const permanent =
			(response.status === 400 || response.status === 401) &&
			oauthError !== "temporarily_unavailable" &&
			oauthError !== "server_error";
		throw new WhoopTokenError(
			response.status,
			oauthError,
			permanent,
			`WHOOP rechazó la petición de token (${response.status}${oauthError ? ` ${oauthError}` : ""}): ${description}`,
		);
	}
	return json;
}

function toTokens(raw: RawTokenResponse, previousRefreshToken: string | null): WhoopTokens {
	if (typeof raw.access_token !== "string" || raw.access_token.length === 0) {
		throw new WhoopTokenError(200, null, false, "WHOOP devolvió una respuesta de token sin access_token.");
	}
	const expiresIn =
		typeof raw.expires_in === "number" && Number.isFinite(raw.expires_in) && raw.expires_in > 0
			? raw.expires_in
			: 3600;
	return {
		accessToken: raw.access_token,
		refreshToken:
			typeof raw.refresh_token === "string" && raw.refresh_token.length > 0
				? raw.refresh_token
				: previousRefreshToken,
		expiresAt: Date.now() + expiresIn * 1000,
		scope: typeof raw.scope === "string" ? raw.scope : WHOOP_SCOPE_STRING,
	};
}

export async function exchangeWhoopCode(
	params: WhoopCredentials & { code: string; redirectUri: string; codeVerifier: string },
	fetchImpl: typeof fetch = fetch,
): Promise<WhoopTokens> {
	const body = new URLSearchParams({
		grant_type: "authorization_code",
		code: params.code,
		client_id: params.clientId,
		client_secret: params.clientSecret,
		redirect_uri: params.redirectUri,
		code_verifier: params.codeVerifier,
	});
	return toTokens(await postTokenEndpoint(body, fetchImpl), null);
}

export async function refreshWhoopTokens(
	params: WhoopCredentials & { refreshToken: string },
	fetchImpl: typeof fetch = fetch,
): Promise<WhoopTokens> {
	const body = new URLSearchParams({
		grant_type: "refresh_token",
		refresh_token: params.refreshToken,
		client_id: params.clientId,
		client_secret: params.clientSecret,
		// Imprescindible: sin `offline` WHOOP no rota el refresh token (ver cabecera).
		scope: WHOOP_SCOPE_STRING,
	});
	return toTokens(await postTokenEndpoint(body, fetchImpl), params.refreshToken);
}
