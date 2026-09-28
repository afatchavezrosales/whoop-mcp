import { env, runDurableObjectAlarm } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { pkceChallenge } from "../../src/whoop/oauth";

// Flujo completo con WHOOP simulado: DCR → consentimiento → redirect a WHOOP →
// callback → /token → /mcp (tools/list + tools/call) → refresh del token MCP.
// Ninguna petición sale a Internet: fetch se intercepta para las URLs de WHOOP.

const BASE = "https://whoop-mcp.your-subdomain.workers.dev";
const CLIENT_REDIRECT = "https://client.example.com/oauth/callback";
const WHOOP_TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token";
const WHOOP_API = "https://api.prod.whoop.com/developer";

// PKCE del cliente MCP.
const CLIENT_VERIFIER = "client-test-verifier-0123456789-abcdefghijklmnopqrstuvwxyz";
const CLIENT_CHALLENGE = await pkceChallenge(CLIENT_VERIFIER);

const SLEEP_ID = "ecfc6a15-4661-442f-a9a4-f160dd7afae8";
const WORKOUT_ID = "0f3e4b3a-9b53-4a3c-8d7e-2f7f0b1a2c3d";

const realFetch = globalThis.fetch;
let whoopCalls: Array<{ url: string; init?: RequestInit }> = [];
let whoopUserId = 777001;

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
	whoopCalls = [];
	whoopUserId += 1;
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		if (!url.startsWith("https://api.prod.whoop.com/")) return realFetch(input, init);
		whoopCalls.push({ url, init });
		if (url === WHOOP_TOKEN_URL) {
			return json({ access_token: "whoop-at-1", refresh_token: "whoop-rt-1", expires_in: 3600, scope: "offline read:recovery", token_type: "bearer" });
		}
		if (url === `${WHOOP_API}/v2/user/profile/basic`) {
			return json({ user_id: whoopUserId, email: "a@example.com", first_name: "Ana", last_name: "Test" });
		}
		if (url === `${WHOOP_API}/v2/user/access`) {
			return init?.method === "DELETE" ? new Response(null, { status: 204 }) : json({ message: "method" }, 405);
		}
		if (url === `${WHOOP_API}/v2/cycle/93845/recovery`) {
			return json({ cycle_id: 93845, sleep_id: SLEEP_ID, score: { recovery_score: 44 } });
		}
		if (url === `${WHOOP_API}/v2/cycle/93845/sleep`) {
			return json({ id: SLEEP_ID, cycle_id: 93845, score: { sleep_performance_percentage: 91 } });
		}
		if (url === `${WHOOP_API}/v2/cycle/93845`) {
			return json({ id: 93845, score: { strain: 5.2 } });
		}
		if (url === `${WHOOP_API}/v2/activity/sleep/${SLEEP_ID}`) {
			return json({ id: SLEEP_ID, cycle_id: 93845 });
		}
		if (url === `${WHOOP_API}/v2/activity/workout/${WORKOUT_ID}`) {
			return json({ id: WORKOUT_ID, sport_name: "running", score: { strain: 8.1 } });
		}
		if (url.startsWith(`${WHOOP_API}/v2/recovery`)) {
			return json({ records: [{ cycle_id: 1, score: { recovery_score: 71, hrv_rmssd_milli: 55.2 } }], next_token: null });
		}
		if (url.startsWith(`${WHOOP_API}/v2/cycle`)) {
			return json({ records: [{ id: 9, score: { strain: 12.4 } }], next_token: null });
		}
		if (url.startsWith(`${WHOOP_API}/v2/activity/sleep`)) {
			return json({ records: [{ id: "s1", score: { sleep_performance_percentage: 88 } }], next_token: null });
		}
		return json({ message: "not found" }, 404);
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

function call(path: string, init?: RequestInit): Promise<Response> {
	return exports.default.fetch(new Request(`${BASE}${path}`, { redirect: "manual", ...init }));
}

function cookiesFrom(response: Response): string {
	return response.headers
		.getSetCookie()
		.map((cookie) => cookie.split(";")[0])
		.filter((pair) => pair && !pair.endsWith("="))
		.join("; ");
}

async function registerClient(): Promise<string> {
	const response = await call("/register", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			client_name: "Client <script>alert(1)</script>",
			redirect_uris: [CLIENT_REDIRECT],
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			token_endpoint_auth_method: "none",
		}),
	});
	expect(response.status).toBe(201);
	return ((await response.json()) as { client_id: string }).client_id;
}

async function rpc(accessToken: string, id: number, method: string, params?: unknown): Promise<any> {
	const response = await call("/mcp", {
		method: "POST",
		headers: {
			Authorization: `Bearer ${accessToken}`,
			// En producción lo pone Cloudflare; el handler MCP valida Host (anti DNS-rebinding).
			Host: new URL(BASE).host,
			"Content-Type": "application/json",
			Accept: "application/json, text/event-stream",
			"MCP-Protocol-Version": "2025-06-18",
		},
		body: JSON.stringify({ jsonrpc: "2.0", id, method, ...(params === undefined ? {} : { params }) }),
	});
	const text = await response.text();
	expect(response.status, text).toBe(200);
	const payload = (response.headers.get("Content-Type") ?? "").includes("text/event-stream")
		? text
				.split("\n")
				.filter((line) => line.startsWith("data:"))
				.map((line) => line.slice(5).trim())
				.pop()!
		: text;
	return JSON.parse(payload);
}

async function connect(): Promise<{ clientId: string; accessToken: string; refreshToken: string }> {
	const clientId = await registerClient();

	// 1) /authorize → página de consentimiento (el nombre del cliente sale escapado).
	const authorizeParams = new URLSearchParams({
		response_type: "code",
		client_id: clientId,
		redirect_uri: CLIENT_REDIRECT,
		code_challenge: CLIENT_CHALLENGE,
		code_challenge_method: "S256",
		state: "client-state-123",
		scope: "whoop:read",
		resource: `${BASE}/mcp`,
	});
	const consent = await call(`/authorize?${authorizeParams}`);
	expect(consent.status).toBe(200);
	const html = await consent.text();
	expect(html).not.toContain("<script>alert(1)</script>");
	expect(html).toContain("&#60;script&#62;");
	const handle = /name="handle" value="([^"]+)"/.exec(html)?.[1];
	expect(handle).toBeTruthy();

	// 2) Aprobar → redirect a WHOOP con los scopes de lectura, PKCE y nuestra redirect URI.
	const approve = await call("/authorize", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookiesFrom(consent) },
		body: new URLSearchParams({ handle: handle!, decision: "approve" }).toString(),
	});
	expect(approve.status).toBe(302);
	const whoopAuthorize = new URL(approve.headers.get("Location")!);
	expect(whoopAuthorize.origin + whoopAuthorize.pathname).toBe("https://api.prod.whoop.com/oauth/oauth2/auth");
	expect(whoopAuthorize.searchParams.get("client_id")).toBe("test-client-id");
	expect(whoopAuthorize.searchParams.get("redirect_uri")).toBe(`${BASE}/callback`);
	expect(whoopAuthorize.searchParams.get("scope")).toBe(
		"offline read:profile read:body_measurement read:recovery read:cycles read:sleep read:workout",
	);
	expect(whoopAuthorize.searchParams.get("code_challenge_method")).toBe("S256");
	const upstreamState = whoopAuthorize.searchParams.get("state")!;
	expect(upstreamState.length).toBeGreaterThanOrEqual(8);

	// 3) WHOOP vuelve al callback → canje del code → redirect al cliente MCP con su code.
	const callback = await call(`/callback?code=whoop-code&state=${encodeURIComponent(upstreamState)}`, {
		headers: { Cookie: cookiesFrom(approve) },
	});
	expect(callback.status).toBe(302);
	const back = new URL(callback.headers.get("Location")!);
	expect(back.origin + back.pathname).toBe(CLIENT_REDIRECT);
	expect(back.searchParams.get("state")).toBe("client-state-123");
	const code = back.searchParams.get("code")!;
	expect(code).toBeTruthy();

	const tokenCall = whoopCalls.find((c) => c.url === WHOOP_TOKEN_URL)!;
	const tokenBody = new URLSearchParams(String(tokenCall.init?.body));
	expect(tokenBody.get("grant_type")).toBe("authorization_code");
	expect(tokenBody.get("client_secret")).toBe("test-client-secret");
	expect(tokenBody.get("redirect_uri")).toBe(`${BASE}/callback`);
	expect(tokenBody.get("code_verifier")?.length).toBeGreaterThanOrEqual(43);

	// 4) El cliente MCP canjea su code por NUESTROS tokens.
	const token = await call("/token", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: CLIENT_REDIRECT,
			client_id: clientId,
			code_verifier: CLIENT_VERIFIER,
			resource: `${BASE}/mcp`,
		}).toString(),
	});
	expect(token.status).toBe(200);
	const tokens = (await token.json()) as { access_token: string; refresh_token: string; scope: string };
	expect(tokens.scope).toBe("whoop:read");
	expect(tokens.access_token).not.toContain("whoop-at-1");
	return { clientId, accessToken: tokens.access_token, refreshToken: tokens.refresh_token };
}

describe("flujo OAuth completo + tools", () => {
	it("conecta, lista las tools (todas de solo lectura salvo disconnect_whoop) y consulta la recuperación", async () => {
		const { accessToken } = await connect();

		// El handshake anuncia el icono servido por el propio Worker (spec 2025-11).
		const init = await rpc(accessToken, 100, "initialize", {
			protocolVersion: "2025-06-18",
			capabilities: {},
			clientInfo: { name: "test", version: "1.0.0" },
		});
		expect(init.result.serverInfo.icons).toEqual([
			{ src: `${BASE}/icon.svg`, mimeType: "image/svg+xml", sizes: ["any"] },
		]);

		const list = await rpc(accessToken, 1, "tools/list");
		const tools = list.result.tools as Array<{ name: string; annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean } }>;
		expect(tools.map((t) => t.name).sort()).toEqual([
			"disconnect_whoop",
			"get_body_measurement",
			"get_cycle",
			"get_cycle_collection",
			"get_cycle_recovery",
			"get_cycle_sleep",
			"get_latest_overview",
			"get_profile",
			"get_recovery_collection",
			"get_sleep",
			"get_sleep_collection",
			"get_workout",
			"get_workout_collection",
		]);
		for (const tool of tools) {
			if (tool.name === "disconnect_whoop") {
				expect(tool.annotations?.readOnlyHint).toBe(false);
				expect(tool.annotations?.destructiveHint).toBe(true);
			} else {
				expect(tool.annotations?.readOnlyHint).toBe(true);
			}
		}

		whoopCalls = [];
		const result = await rpc(accessToken, 2, "tools/call", {
			name: "get_recovery_collection",
			arguments: { start: "2026-09-01", limit: 2 },
		});
		expect(result.result.isError).toBeFalsy();
		expect(JSON.parse(result.result.content[0].text).records[0].score.recovery_score).toBe(71);
		const apiCall = whoopCalls.find((c) => c.url.startsWith(`${WHOOP_API}/v2/recovery`))!;
		expect(apiCall.url).toBe(`${WHOOP_API}/v2/recovery?start=2026-09-01T00%3A00%3A00.000Z&limit=2`);
		expect(new Headers(apiCall.init?.headers).get("Authorization")).toBe("Bearer whoop-at-1");
	});

	it("get_latest_overview combina ciclo, recuperación y sueño", async () => {
		const { accessToken } = await connect();
		const result = await rpc(accessToken, 3, "tools/call", { name: "get_latest_overview", arguments: {} });
		const overview = JSON.parse(result.result.content[0].text);
		expect(overview.latest_cycle.score.strain).toBe(12.4);
		expect(overview.latest_recovery.score.recovery_score).toBe(71);
		expect(overview.latest_sleep.score.sleep_performance_percentage).toBe(88);
	});

	it("rechaza fechas no ISO sin llamar a WHOOP", async () => {
		const { accessToken } = await connect();
		whoopCalls = [];
		const result = await rpc(accessToken, 4, "tools/call", {
			name: "get_sleep_collection",
			arguments: { start: "ayer" },
		});
		const failed = result.error !== undefined || result.result?.isError === true;
		expect(failed).toBe(true);
		expect(whoopCalls).toHaveLength(0);
	});

	it("el refresh del token MCP funciona mientras WHOOP siga conectado, y da invalid_grant si se revocó", async () => {
		const { clientId, refreshToken } = await connect();
		const refresh = (token: string) =>
			call("/token", {
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: token, client_id: clientId }).toString(),
			});

		const ok = await refresh(refreshToken);
		expect(ok.status).toBe(200);
		const rotated = ((await ok.json()) as { refresh_token: string }).refresh_token;

		// WHOOP revoca: el vault queda sin tokens → el siguiente refresh MCP revoca el grant.
		const namespace = env.WHOOP_TOKEN_VAULT;
		await namespace.get(namespace.idFromName(`whoop-user:${whoopUserId}`)).clear();
		const denied = await refresh(rotated);
		expect(denied.status).toBe(400);
		expect(((await denied.json()) as { error: string }).error).toBe("invalid_grant");
	});

	it("si el usuario cancela, vuelve al cliente con access_denied", async () => {
		const clientId = await registerClient();
		const params = new URLSearchParams({
			response_type: "code",
			client_id: clientId,
			redirect_uri: CLIENT_REDIRECT,
			code_challenge: CLIENT_CHALLENGE,
			code_challenge_method: "S256",
			state: "st-deny-1",
			resource: `${BASE}/mcp`,
		});
		const consent = await call(`/authorize?${params}`);
		const handle = /name="handle" value="([^"]+)"/.exec(await consent.text())![1]!;
		const deny = await call("/authorize", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookiesFrom(consent) },
			body: new URLSearchParams({ handle, decision: "deny" }).toString(),
		});
		expect(deny.status).toBe(302);
		const location = new URL(deny.headers.get("Location")!);
		expect(location.searchParams.get("error")).toBe("access_denied");
		expect(location.searchParams.get("state")).toBe("st-deny-1");
	});

	it("el callback sin la cookie del navegador que consintió se rechaza", async () => {
		const response = await call("/callback?code=x&state=forged-state-value");
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});
});

function vaultOf(userId: number | string) {
	const namespace = env.WHOOP_TOKEN_VAULT;
	return namespace.get(namespace.idFromName(`whoop-user:${userId}`));
}

const deleteAccessCalls = () =>
	whoopCalls.filter((c) => c.url === `${WHOOP_API}/v2/user/access` && c.init?.method === "DELETE");

function revoke(clientId: string, token: string, hint?: string): Promise<Response> {
	return call("/token", {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ token, client_id: clientId, ...(hint ? { token_type_hint: hint } : {}) }).toString(),
	});
}

function mcpStatus(accessToken: string): Promise<number> {
	return call("/mcp", {
		method: "POST",
		headers: {
			Authorization: `Bearer ${accessToken}`,
			Host: new URL(BASE).host,
			"Content-Type": "application/json",
			Accept: "application/json, text/event-stream",
		},
		body: JSON.stringify({ jsonrpc: "2.0", id: 99, method: "tools/list" }),
	}).then((response) => response.status);
}

describe("tools por id", () => {
	it("get_cycle, get_cycle_sleep, get_cycle_recovery, get_sleep y get_workout llaman al endpoint v2 correcto", async () => {
		const { accessToken } = await connect();
		const cases: Array<[string, Record<string, unknown>, string]> = [
			["get_cycle", { cycleId: 93845 }, "/v2/cycle/93845"],
			["get_cycle_sleep", { cycleId: 93845 }, "/v2/cycle/93845/sleep"],
			["get_cycle_recovery", { cycleId: 93845 }, "/v2/cycle/93845/recovery"],
			["get_sleep", { sleepId: SLEEP_ID }, `/v2/activity/sleep/${SLEEP_ID}`],
			["get_workout", { workoutId: WORKOUT_ID }, `/v2/activity/workout/${WORKOUT_ID}`],
		];
		let id = 10;
		for (const [name, args, path] of cases) {
			whoopCalls = [];
			const result = await rpc(accessToken, id++, "tools/call", { name, arguments: args });
			expect(result.result.isError, name).toBeFalsy();
			expect(whoopCalls.map((c) => c.url)).toEqual([`${WHOOP_API}${path}`]);
			expect(new Headers(whoopCalls[0]!.init?.headers).get("Authorization")).toBe("Bearer whoop-at-1");
		}
		const recovery = await rpc(accessToken, id++, "tools/call", { name: "get_cycle_recovery", arguments: { cycleId: 93845 } });
		expect(JSON.parse(recovery.result.content[0].text).score.recovery_score).toBe(44);
	});

	it("rechaza ids mal formados sin llamar a WHOOP", async () => {
		const { accessToken } = await connect();
		whoopCalls = [];
		const bad: Array<[string, Record<string, unknown>]> = [
			["get_sleep", { sleepId: "../user/profile/basic" }],
			["get_workout", { workoutId: "not-a-uuid" }],
			["get_cycle", { cycleId: -1 }],
			["get_cycle_recovery", { cycleId: 1.5 }],
		];
		let id = 30;
		for (const [name, args] of bad) {
			const result = await rpc(accessToken, id++, "tools/call", { name, arguments: args });
			expect(result.error !== undefined || result.result?.isError === true, name).toBe(true);
		}
		expect(whoopCalls).toHaveLength(0);
	});
});

describe("desconexión y revocación", () => {
	it("revocar el refresh token (RFC 7009) del único cliente revoca el acceso en WHOOP y borra el token", async () => {
		const { clientId, accessToken, refreshToken } = await connect();
		whoopCalls = [];
		const response = await revoke(clientId, refreshToken, "refresh_token");
		expect(response.status).toBe(200);
		await vi.waitFor(() => expect(deleteAccessCalls()).toHaveLength(1), { timeout: 5000 });
		expect(new Headers(deleteAccessCalls()[0]!.init?.headers).get("Authorization")).toBe("Bearer whoop-at-1");
		await vi.waitFor(async () => expect(await vaultOf(whoopUserId).status()).toBe("empty"), { timeout: 5000 });
		expect(await mcpStatus(accessToken)).toBe(401);
	});

	it("revocar solo el access token no desconecta WHOOP", async () => {
		const { clientId, accessToken } = await connect();
		whoopCalls = [];
		expect((await revoke(clientId, accessToken)).status).toBe(200);
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(deleteAccessCalls()).toHaveLength(0);
		expect(await vaultOf(whoopUserId).status()).toBe("connected");
	});

	it("con otro cliente MCP aún conectado, revocar un grant no desconecta WHOOP", async () => {
		const first = await connect();
		const second = await connect();
		whoopCalls = [];
		expect((await revoke(first.clientId, first.refreshToken, "refresh_token")).status).toBe(200);
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(deleteAccessCalls()).toHaveLength(0);
		expect(await vaultOf(whoopUserId).status()).toBe("connected");
		expect(await mcpStatus(second.accessToken)).toBe(200);
	});

	it("un token inventado con el formato del provider no desconecta a nadie", async () => {
		const { clientId } = await connect();
		whoopCalls = [];
		const forged = `whoop-${whoopUserId}:grant-que-no-existe:secreto`;
		expect((await revoke(clientId, forged, "refresh_token")).status).toBe(200);
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(deleteAccessCalls()).toHaveLength(0);
		expect(await vaultOf(whoopUserId).status()).toBe("connected");
	});

	it("la tool disconnect_whoop exige confirm=true, revoca WHOOP y todos los grants del usuario", async () => {
		const first = await connect();
		const second = await connect();
		whoopCalls = [];
		const refused = await rpc(first.accessToken, 50, "tools/call", { name: "disconnect_whoop", arguments: {} });
		expect(refused.error !== undefined || refused.result?.isError === true).toBe(true);
		expect(deleteAccessCalls()).toHaveLength(0);

		const result = await rpc(first.accessToken, 51, "tools/call", { name: "disconnect_whoop", arguments: { confirm: true } });
		expect(result.result.isError).toBeFalsy();
		expect(JSON.parse(result.result.content[0].text)).toEqual({
			disconnected: true,
			whoop_access_revoked: true,
			mcp_grants_revoked: 2,
		});
		expect(deleteAccessCalls()).toHaveLength(1);
		expect(await vaultOf(whoopUserId).status()).toBe("empty");
		expect(await mcpStatus(first.accessToken)).toBe(401);
		expect(await mcpStatus(second.accessToken)).toBe(401);
	});

	it("POST /mcp/disconnect con el Bearer del usuario lo desconecta; sin token da 401", async () => {
		const anonymous = await call("/mcp/disconnect", { method: "POST" });
		expect(anonymous.status).toBe(401);

		const { accessToken } = await connect();
		whoopCalls = [];
		const response = await call("/mcp/disconnect", { method: "POST", headers: { Authorization: `Bearer ${accessToken}` } });
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ disconnected: true, whoop_access_revoked: true, mcp_grants_revoked: 1 });
		expect(deleteAccessCalls()).toHaveLength(1);
		expect(await vaultOf(whoopUserId).status()).toBe("empty");
	});

	it("la alarma del vault desconecta si no queda ningún grant vigente y no toca nada si queda alguno", async () => {
		const orphan = vaultOf("990001");
		await orphan.storeTokens({ accessToken: "at-orphan", refreshToken: "rt", expiresAt: Date.now() + 3_600_000, scope: "offline" }, "990001");
		whoopCalls = [];
		expect(await runDurableObjectAlarm(orphan)).toBe(true);
		expect(deleteAccessCalls()).toHaveLength(1);
		expect(new Headers(deleteAccessCalls()[0]!.init?.headers).get("Authorization")).toBe("Bearer at-orphan");
		expect(await orphan.status()).toBe("empty");

		await connect();
		whoopCalls = [];
		expect(await runDurableObjectAlarm(vaultOf(whoopUserId))).toBe(true);
		expect(deleteAccessCalls()).toHaveLength(0);
		expect(await vaultOf(whoopUserId).status()).toBe("connected");
	});
});
