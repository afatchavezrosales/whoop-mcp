import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { collectionInput } from "../../src/mcp-server";
import { buildCollectionQuery, createWhoopApi, WhoopApiError } from "../../src/whoop/api";
import { refreshWhoopTokens, WhoopTokenError } from "../../src/whoop/oauth";

const WHOOP_TOKEN_URL = "https://api.prod.whoop.com/oauth/oauth2/token";
const realFetch = globalThis.fetch;

afterEach(() => {
	vi.restoreAllMocks();
});

function vault(name: string) {
	const namespace = env.WHOOP_TOKEN_VAULT;
	return namespace.get(namespace.idFromName(`whoop-user:${name}`));
}

/** Error de una llamada RPC al DO (las RpcPromise rechazadas se reportan como no manejadas si se pasan a expect().rejects). */
async function rpcError(call: () => Promise<unknown>): Promise<Error> {
	try {
		await call();
	} catch (error) {
		return error as Error;
	}
	throw new Error("se esperaba un error");
}

function mockTokenEndpoint(handler: (body: URLSearchParams) => Response | Promise<Response>) {
	const bodies: URLSearchParams[] = [];
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		if (url !== WHOOP_TOKEN_URL) return realFetch(input, init);
		const body = new URLSearchParams(String(init?.body));
		bodies.push(body);
		return handler(body);
	});
	return bodies;
}

describe("WhoopTokenVault", () => {
	it("devuelve el token vigente sin llamar a WHOOP", async () => {
		const bodies = mockTokenEndpoint(() => new Response("{}", { status: 500 }));
		const stub = vault("fresh");
		await stub.storeTokens({ accessToken: "at-ok", refreshToken: "rt-ok", expiresAt: Date.now() + 3_600_000, scope: "offline" });
		expect(await stub.getAccessToken()).toBe("at-ok");
		expect(bodies).toHaveLength(0);
		expect(await stub.status()).toBe("connected");
	});

	it("serializa refrescos concurrentes: un solo uso del refresh token (WHOOP lo rota)", async () => {
		const bodies = mockTokenEndpoint(async () => {
			await new Promise((resolve) => setTimeout(resolve, 30));
			return Response.json({ access_token: "at-new", refresh_token: "rt-new", expires_in: 3600, scope: "offline" });
		});
		const stub = vault("concurrent");
		await stub.storeTokens({ accessToken: "at-old", refreshToken: "rt-old", expiresAt: Date.now() - 1000, scope: "offline" });

		const tokens = await Promise.all([stub.getAccessToken(), stub.getAccessToken(), stub.getAccessToken()]);
		expect(tokens).toEqual(["at-new", "at-new", "at-new"]);
		expect(bodies).toHaveLength(1);
		expect(bodies[0]!.get("grant_type")).toBe("refresh_token");
		expect(bodies[0]!.get("refresh_token")).toBe("rt-old");
		// Sin `offline` en el refresh, WHOOP no rota el refresh token y la conexión muere.
		expect(bodies[0]!.get("scope")?.split(" ")).toContain("offline");

		// El refresh token rotado quedó persistido para el siguiente refresh.
		expect(await stub.getAccessToken("at-new")).toBe("at-new");
		expect(bodies).toHaveLength(2);
		expect(bodies[1]!.get("refresh_token")).toBe("rt-new");
	});

	it("con el token rechazado ya rotado por otro, no vuelve a refrescar", async () => {
		const bodies = mockTokenEndpoint(() => Response.json({ access_token: "x", refresh_token: "y", expires_in: 3600 }));
		const stub = vault("already-rotated");
		await stub.storeTokens({ accessToken: "at-current", refreshToken: "rt", expiresAt: Date.now() + 3_600_000, scope: "offline" });
		expect(await stub.getAccessToken("at-stale")).toBe("at-current");
		expect(bodies).toHaveLength(0);
	});

	it("invalid_grant de WHOOP marca la cuenta como revocada y pide reconectar", async () => {
		mockTokenEndpoint(() => Response.json({ error: "invalid_grant", error_description: "refresh token expired" }, { status: 400 }));
		const stub = vault("revoked");
		await stub.storeTokens({ accessToken: "at", refreshToken: "rt", expiresAt: Date.now() - 1000, scope: "offline" });
		expect((await rpcError(() => stub.getAccessToken())).message).toMatch(/^REAUTH:/);
		expect(await stub.status()).toBe("revoked");
		expect((await rpcError(() => stub.getAccessToken())).message).toMatch(/^REAUTH:/);
	});

	it("un 5xx de WHOOP es transitorio: no borra los tokens", async () => {
		mockTokenEndpoint(() => new Response("upstream down", { status: 503 }));
		const stub = vault("transient");
		await stub.storeTokens({ accessToken: "at", refreshToken: "rt", expiresAt: Date.now() - 1000, scope: "offline" });
		expect((await rpcError(() => stub.getAccessToken())).message).toMatch(/503/);
		expect(await stub.status()).toBe("connected");
	});
});

describe("cliente de la API de WHOOP", () => {
	it("ante un 401 fuerza un refresh (pasando el token rechazado) y reintenta una vez", async () => {
		const seen: string[] = [];
		const fetchImpl = (async (_url: string, init?: RequestInit) => {
			const auth = new Headers(init?.headers).get("Authorization")!;
			seen.push(auth);
			return auth === "Bearer t2" ? Response.json({ ok: true }) : new Response("expired", { status: 401 });
		}) as typeof fetch;
		const getAccessToken = vi.fn(async (rejected?: string) => (rejected === "t1" ? "t2" : "t1"));
		const api = createWhoopApi({ getAccessToken, fetchImpl });
		expect(await api.get("/v2/cycle")).toEqual({ ok: true });
		expect(seen).toEqual(["Bearer t1", "Bearer t2"]);
		expect(getAccessToken).toHaveBeenLastCalledWith("t1");
	});

	it("un segundo 401 tras el refresh se propaga como error", async () => {
		const fetchImpl = (async () => new Response("nope", { status: 401 })) as unknown as typeof fetch;
		const api = createWhoopApi({ getAccessToken: async () => "t", fetchImpl });
		await expect(api.get("/v2/cycle")).rejects.toBeInstanceOf(WhoopApiError);
	});

	it("reintenta los 429 respetando Retry-After", async () => {
		let calls = 0;
		const fetchImpl = (async () => {
			calls += 1;
			return calls === 1
				? new Response("slow down", { status: 429, headers: { "Retry-After": "0" } })
				: Response.json({ records: [] });
		}) as unknown as typeof fetch;
		const api = createWhoopApi({ getAccessToken: async () => "t", fetchImpl });
		expect(await api.get("/v2/recovery")).toEqual({ records: [] });
		expect(calls).toBe(2);
	});

	it("construye la query de colecciones omitiendo lo vacío", () => {
		expect(buildCollectionQuery({})).toBe("");
		expect(buildCollectionQuery({ limit: 5, nextToken: "abc" })).toBe("?limit=5&nextToken=abc");
	});

	it("valida fechas ISO y límites", () => {
		expect(collectionInput.safeParse({ start: "2026-09-01", end: "2026-09-02T06:30:00Z", limit: 25 }).success).toBe(true);
		expect(collectionInput.safeParse({ start: "ayer" }).success).toBe(false);
		expect(collectionInput.safeParse({ start: "2026-13-45" }).success).toBe(false);
		expect(collectionInput.safeParse({ limit: 26 }).success).toBe(false);
	});
});

describe("refresh contra WHOOP", () => {
	it("400 invalid_grant es permanente; 429 no", async () => {
		const permanent = refreshWhoopTokens(
			{ clientId: "c", clientSecret: "s", refreshToken: "r" },
			(async () => Response.json({ error: "invalid_grant" }, { status: 400 })) as unknown as typeof fetch,
		);
		await expect(permanent).rejects.toMatchObject({ permanent: true, oauthError: "invalid_grant" });

		const transient = refreshWhoopTokens(
			{ clientId: "c", clientSecret: "s", refreshToken: "r" },
			(async () => new Response("", { status: 429 })) as unknown as typeof fetch,
		);
		await expect(transient).rejects.toBeInstanceOf(WhoopTokenError);
		await expect(transient).rejects.toMatchObject({ permanent: false });
	});

	it("conserva el refresh token anterior si WHOOP no devuelve uno nuevo", async () => {
		const tokens = await refreshWhoopTokens(
			{ clientId: "c", clientSecret: "s", refreshToken: "r-prev" },
			(async () => Response.json({ access_token: "a", expires_in: 60 })) as unknown as typeof fetch,
		);
		expect(tokens.refreshToken).toBe("r-prev");
		expect(tokens.expiresAt).toBeGreaterThan(Date.now());
	});
});
