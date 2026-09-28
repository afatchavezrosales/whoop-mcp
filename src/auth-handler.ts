import {
	AuthorizationError,
	CimdFetchError,
	authorizationErrorRedirect,
	type AuthRequest,
	type OAuthHelpers,
	type RememberConsentOptions,
} from "@cloudflare/workers-oauth-provider";
import { mcpUserIdFor } from "./grants";
import { renderConsentPage, renderErrorPage } from "./html";
import { ICON_PATH, iconResponse } from "./icon";
import { SERVER_NAME, SERVER_VERSION } from "./mcp-server";
import { vaultFor } from "./token-vault";
import { WHOOP_API_BASE_URL, WHOOP_ENDPOINTS } from "./whoop/api";
import {
	WHOOP_CALLBACK_PATH,
	WHOOP_SCOPES,
	buildWhoopAuthorizeUrl,
	exchangeWhoopCode,
	generatePkceVerifier,
	pkceChallenge,
	whoopCredentials,
	whoopRedirectUri,
} from "./whoop/oauth";

// =============================================================================
// defaultHandler del OAuthProvider: todo lo que NO es /mcp ni los endpoints
// que gestiona la librería (/token, /register, /.well-known/*).
//
//   GET  /           estado del servicio (sin secretos)
//   GET  /authorize  valida la petición OAuth del cliente MCP y pide consentimiento
//   POST /authorize  consentimiento → redirige a WHOOP (state ligado al navegador)
//   GET  /callback   WHOOP vuelve aquí: canjea el code, guarda el token y emite el nuestro
//
// Patrón oficial "signing in through another provider" de
// @cloudflare/workers-oauth-provider 1.2 (consent por cliente antes del redirect
// para evitar el confused deputy; handle/state de un solo uso y ligados a cookie).
// =============================================================================

/** Scope único que concede este servidor (todas las tools son de lectura). */
export const MCP_SCOPE = "whoop:read";

/** Lo que viaja cifrado en el grant y llega a las tools como props. */
export interface AuthProps extends Record<string, unknown> {
	whoopUserId: string;
}

type HandlerEnv = Env & { OAUTH_PROVIDER: OAuthHelpers };

const PROFILE_TIMEOUT_MS = 15_000;

function notConfigured(): Response {
	return renderErrorPage(
		503,
		"Servidor WHOOP MCP sin configurar",
		"Faltan los secretos WHOOP_CLIENT_ID y WHOOP_CLIENT_SECRET del Worker. El administrador debe configurarlos con `wrangler secret put` antes de conectar cuentas.",
	);
}

function rememberOptions(env: Env): Pick<RememberConsentOptions, "secret"> | null {
	const secret = env.CONSENT_SECRET?.trim();
	return secret && secret.length >= 32 ? { secret } : null;
}

function redirect(location: string, headers = new Headers()): Response {
	headers.set("Location", location);
	headers.set("Cache-Control", "no-store");
	return new Response(null, { status: 302, headers });
}

/** Errores esperados del flujo OAuth → redirect seguro al cliente o página local. */
function handleAuthorizeError(error: unknown): Response {
	if (error instanceof AuthorizationError && error.redirectTo) {
		return redirect(error.redirectTo);
	}
	if (error instanceof AuthorizationError) {
		return renderErrorPage(400, "No se pudo completar la autorización", error.description || "La petición no es válida o ha caducado. Vuelve a iniciar la conexión desde la aplicación.");
	}
	if (error instanceof CimdFetchError) {
		return renderErrorPage(400, "Aplicación no verificable", "No se pudo obtener el documento de metadatos de la aplicación cliente.");
	}
	throw error;
}

async function startWhoopRedirect(
	env: HandlerEnv,
	authRequest: AuthRequest,
	headers: Headers | undefined,
): Promise<Response> {
	const credentials = whoopCredentials(env);
	if (!credentials) return notConfigured();
	const verifier = generatePkceVerifier();
	const upstream = await env.OAUTH_PROVIDER.beginUpstream(authRequest, {
		data: { verifier },
		headers,
	});
	const location = buildWhoopAuthorizeUrl({
		clientId: credentials.clientId,
		redirectUri: whoopRedirectUri(env.PUBLIC_BASE_URL),
		state: upstream.state,
		codeChallenge: await pkceChallenge(verifier),
	});
	return redirect(location, upstream.headers);
}

async function getAuthorize(request: Request, env: HandlerEnv): Promise<Response> {
	let authRequest: AuthRequest;
	try {
		authRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
	} catch (error) {
		return handleAuthorizeError(error);
	}
	if (!whoopCredentials(env)) return notConfigured();

	try {
		const remember = rememberOptions(env);
		if (remember && (await env.OAUTH_PROVIDER.isConsentRemembered(request, authRequest, remember))) {
			// Consentimiento ya dado a este cliente+redirect en este navegador: directo a WHOOP.
			const scoped: AuthRequest = { ...authRequest, scope: [MCP_SCOPE] };
			return await startWhoopRedirect(env, scoped, undefined);
		}
		const details = await env.OAUTH_PROVIDER.describeConsent(authRequest);
		const consent = await env.OAUTH_PROVIDER.beginConsent(authRequest);
		return renderConsentPage(details, consent.handle, consent.headers);
	} catch (error) {
		return handleAuthorizeError(error);
	}
}

async function postAuthorize(request: Request, env: HandlerEnv): Promise<Response> {
	let form: FormData;
	try {
		form = await request.formData();
	} catch {
		return renderErrorPage(400, "Petición no válida", "El formulario de autorización no es válido.");
	}
	const handle = String(form.get("handle") ?? "");
	try {
		if (form.get("decision") !== "approve") {
			const denied = await env.OAUTH_PROVIDER.denyConsent(request, handle);
			return new Response(null, { status: 302, headers: denied.headers });
		}
		if (!whoopCredentials(env)) return notConfigured();
		const remember = rememberOptions(env);
		const approved = await env.OAUTH_PROVIDER.approveConsent(request, handle, {
			scope: [MCP_SCOPE],
			...(remember ? { remember } : {}),
		});
		return await startWhoopRedirect(env, approved.request, approved.headers);
	} catch (error) {
		return handleAuthorizeError(error);
	}
}

async function fetchWhoopUserId(accessToken: string): Promise<string> {
	const response = await fetch(`${WHOOP_API_BASE_URL}${WHOOP_ENDPOINTS.profile}`, {
		headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
		signal: AbortSignal.timeout(PROFILE_TIMEOUT_MS),
	});
	if (!response.ok) {
		throw new Error(`WHOOP no devolvió el perfil (${response.status}).`);
	}
	const profile = (await response.json()) as { user_id?: unknown };
	if (typeof profile.user_id !== "number" && typeof profile.user_id !== "string") {
		throw new Error("El perfil de WHOOP no incluye user_id.");
	}
	return String(profile.user_id);
}

async function getCallback(request: Request, env: HandlerEnv): Promise<Response> {
	let resumed: Awaited<ReturnType<OAuthHelpers["finishUpstream"]>> & { data: { verifier?: unknown } };
	try {
		resumed = (await env.OAUTH_PROVIDER.finishUpstream<{ verifier?: unknown }>(request)) as typeof resumed;
	} catch (error) {
		return handleAuthorizeError(error);
	}
	const { request: original, data, headers } = resumed;
	const url = new URL(request.url);

	if (url.searchParams.get("error")) {
		// El usuario rechazó en WHOOP (o WHOOP falló): se lo decimos al cliente MCP.
		return redirect(authorizationErrorRedirect(original, "access_denied", "WHOOP no concedió el acceso."), headers);
	}

	const credentials = whoopCredentials(env);
	if (!credentials) return notConfigured();

	const code = url.searchParams.get("code");
	const verifier = typeof data?.verifier === "string" ? data.verifier : null;
	if (!code || !verifier) {
		return renderErrorPage(400, "Respuesta de WHOOP incompleta", "Falta el código de autorización. Vuelve a iniciar la conexión desde la aplicación.", headers);
	}

	try {
		const tokens = await exchangeWhoopCode({
			...credentials,
			code,
			codeVerifier: verifier,
			redirectUri: whoopRedirectUri(env.PUBLIC_BASE_URL),
		});
		if (!tokens.refreshToken) {
			console.warn("WHOOP no devolvió refresh_token: la conexión caducará con el access token.");
		}
		const whoopUserId = await fetchWhoopUserId(tokens.accessToken);
		await vaultFor(env, whoopUserId).storeTokens(tokens, whoopUserId);

		const props: AuthProps = { whoopUserId };
		const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
			request: original,
			userId: mcpUserIdFor(whoopUserId),
			metadata: {},
			scope: original.scope.length > 0 ? original.scope : [MCP_SCOPE],
			props,
		});
		return redirect(redirectTo, headers);
	} catch (error) {
		const detail = error instanceof Error ? error.message : "error desconocido.";
		console.error("Callback de WHOOP fallido:", detail);
		return renderErrorPage(502, "No se pudo conectar con WHOOP", `${detail} Vuelve a intentarlo desde la aplicación.`, headers);
	}
}

function getStatus(env: Env): Response {
	return Response.json(
		{
			name: SERVER_NAME,
			version: SERVER_VERSION,
			mcp_endpoint: `${env.PUBLIC_BASE_URL}/mcp`,
			whoop_configured: whoopCredentials(env) !== null,
			whoop_redirect_uri: whoopRedirectUri(env.PUBLIC_BASE_URL),
			whoop_scopes: WHOOP_SCOPES,
			read_only: true,
		},
		{ headers: { "Cache-Control": "no-store" } },
	);
}

export const authHandler = {
	async fetch(request: Request, env: HandlerEnv): Promise<Response> {
		const { pathname } = new URL(request.url);
		if (pathname === "/" && request.method === "GET") return getStatus(env);
		if (pathname === "/authorize" && request.method === "GET") return getAuthorize(request, env);
		if (pathname === "/authorize" && request.method === "POST") return postAuthorize(request, env);
		if (pathname === WHOOP_CALLBACK_PATH && request.method === "GET") return getCallback(request, env);
		if (pathname === ICON_PATH) return iconResponse(request);
		if (pathname === "/favicon.ico") return new Response(null, { status: 204 });
		return new Response("Not found", { status: 404 });
	},
} satisfies ExportedHandler<HandlerEnv>;
