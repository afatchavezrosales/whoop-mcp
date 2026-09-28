import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

// Superficie pública del Worker SIN los secretos de WHOOP (estado del primer deploy).

const BASE = "https://whoop-mcp.your-subdomain.workers.dev";
const CLIENT_REDIRECT = "https://client.example.com/oauth/callback";

function call(path: string, init?: RequestInit): Promise<Response> {
	return exports.default.fetch(new Request(`${BASE}${path}`, init));
}

async function registerClient(): Promise<string> {
	const response = await call("/register", {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			client_name: "Test client",
			redirect_uris: [CLIENT_REDIRECT],
			grant_types: ["authorization_code", "refresh_token"],
			response_types: ["code"],
			token_endpoint_auth_method: "none",
		}),
	});
	expect(response.status).toBe(201);
	const body = (await response.json()) as { client_id?: string };
	expect(typeof body.client_id).toBe("string");
	return body.client_id!;
}

describe("metadata OAuth", () => {
	it("publica la metadata del servidor de autorización (RFC 8414) con DCR, PKCE S256 y CIMD", async () => {
		const response = await call("/.well-known/oauth-authorization-server");
		expect(response.status).toBe(200);
		const metadata = (await response.json()) as Record<string, unknown>;
		expect(metadata.issuer).toBe(BASE);
		expect(metadata.authorization_endpoint).toBe(`${BASE}/authorize`);
		expect(metadata.token_endpoint).toBe(`${BASE}/token`);
		expect(metadata.registration_endpoint).toBe(`${BASE}/register`);
		expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
		expect(metadata.scopes_supported).toEqual(["whoop:read"]);
		expect(metadata.client_id_metadata_document_supported).toBe(true);
	});

	it("publica la metadata del recurso protegido (RFC 9728) para /mcp", async () => {
		const response = await call("/.well-known/oauth-protected-resource/mcp");
		expect(response.status).toBe(200);
		const metadata = (await response.json()) as Record<string, unknown>;
		expect(metadata.resource).toBe(`${BASE}/mcp`);
		expect(metadata.authorization_servers).toEqual([BASE]);
		expect(metadata.scopes_supported).toEqual(["whoop:read"]);
	});
});

describe("/mcp exige autenticación", () => {
	it("responde 401 con challenge Bearer sin token", async () => {
		const response = await call("/mcp", {
			method: "POST",
			headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
		});
		expect(response.status).toBe(401);
		const challenge = response.headers.get("WWW-Authenticate") ?? "";
		expect(challenge).toMatch(/^Bearer /);
		expect(challenge).toContain(`resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`);
	});

	it("responde 401 con un token inventado", async () => {
		const response = await call("/mcp", {
			method: "POST",
			headers: {
				Authorization: "Bearer not-a-real-token",
				"Content-Type": "application/json",
				Accept: "application/json, text/event-stream",
			},
			body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
		});
		expect(response.status).toBe(401);
	});
});

describe("icono del servidor", () => {
	it("GET /icon.svg sirve un SVG propio, cacheable y sin scripts", async () => {
		const response = await call("/icon.svg");
		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toMatch(/^image\/svg\+xml/);
		expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
		expect(response.headers.get("Content-Security-Policy")).toContain("default-src 'none'");
		expect(response.headers.get("Cross-Origin-Resource-Policy")).toBe("cross-origin");
		const svg = await response.text();
		expect(svg.startsWith("<svg")).toBe(true);
		expect(svg).not.toMatch(/<script|href=|on[a-z]+=/i);
	});

	it("HEAD /icon.svg responde sin cuerpo y otros métodos dan 405", async () => {
		const head = await call("/icon.svg", { method: "HEAD" });
		expect(head.status).toBe(200);
		expect(await head.text()).toBe("");
		const post = await call("/icon.svg", { method: "POST" });
		expect(post.status).toBe(405);
	});
});

describe("sin secretos de WHOOP", () => {
	it("GET / informa de que WHOOP no está configurado, sin exponer secretos", async () => {
		const response = await call("/");
		expect(response.status).toBe(200);
		const status = (await response.json()) as Record<string, unknown>;
		expect(status.whoop_configured).toBe(false);
		expect(status.whoop_redirect_uri).toBe(`${BASE}/callback`);
		expect(status.mcp_endpoint).toBe(`${BASE}/mcp`);
		expect(JSON.stringify(status)).not.toMatch(/secret/i);
	});

	it("DCR funciona y /authorize responde 503 con un error claro", async () => {
		const clientId = await registerClient();
		const params = new URLSearchParams({
			response_type: "code",
			client_id: clientId,
			redirect_uri: CLIENT_REDIRECT,
			code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			code_challenge_method: "S256",
			state: "abc12345",
			scope: "whoop:read",
			resource: `${BASE}/mcp`,
		});
		const response = await call(`/authorize?${params}`);
		expect(response.status).toBe(503);
		const html = await response.text();
		expect(html).toContain("WHOOP_CLIENT_ID");
		expect(response.headers.get("X-Frame-Options")).toBe("DENY");
	});

	it("/authorize con un cliente desconocido NO redirige: renderiza el error", async () => {
		const params = new URLSearchParams({
			response_type: "code",
			client_id: "desconocido",
			redirect_uri: "https://evil.example/cb",
			code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			code_challenge_method: "S256",
		});
		const response = await call(`/authorize?${params}`);
		expect(response.status).toBe(400);
		expect(response.headers.get("Location")).toBeNull();
	});
});

describe("webhook de WHOOP sin secretos", () => {
	it("sin cabeceras de firma válidas responde 401; con firma bien formada, 503 (no se puede verificar)", async () => {
		const body = JSON.stringify({ user_id: 1, id: "a", type: "sleep.updated", trace_id: "t-1" });
		const unsigned = await call("/webhooks/whoop", { method: "POST", body });
		expect(unsigned.status).toBe(401);
		const wellFormed = await call("/webhooks/whoop", {
			method: "POST",
			headers: { "X-WHOOP-Signature-Timestamp": String(Date.now()), "X-WHOOP-Signature": btoa("x".repeat(32)) },
			body,
		});
		expect(wellFormed.status).toBe(503);
	});
});
