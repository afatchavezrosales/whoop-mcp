import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	FORWARD_EVENT_HEADER,
	FORWARD_SIGNATURE_HEADER,
	FORWARD_TIMESTAMP_HEADER,
	FORWARD_TRACE_HEADER,
	handleWhoopWebhook,
	parseForwardUrls,
	signPayload,
	verifySignature,
} from "../../src/webhooks";

// Webhooks de WHOOP v2: verificación de firma + reenvío firmado. WHOOP_CLIENT_SECRET
// es el secreto FALSO del proyecto "configured" (vitest.config.ts).

const BASE = "https://whoop-mcp.your-subdomain.workers.dev";
const WHOOP_SECRET = "test-client-secret";
const FORWARD_SECRET = "forward-secret-for-tests-0123456789abcdef";
const RECEIVER_A = "https://receiver-a.example.com/whoop";
const RECEIVER_B = "https://receiver-b.example.com/hooks?source=whoop";
const WHOOP_API = "https://api.prod.whoop.com/developer";
const SLEEP_ID = "ecfc6a15-4661-442f-a9a4-f160dd7afae8";

const realFetch = globalThis.fetch;
let delivered: Array<{ url: string; headers: Headers; body: string }> = [];
let whoopApiCalls: string[] = [];
let traceCounter = 0;

beforeEach(() => {
	delivered = [];
	whoopApiCalls = [];
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
		if (url.startsWith("https://receiver-")) {
			delivered.push({ url, headers: new Headers(init?.headers), body: String(init?.body) });
			return new Response(null, { status: 204 });
		}
		if (url.startsWith("https://api.prod.whoop.com/")) {
			whoopApiCalls.push(url);
			if (url === `${WHOOP_API}/v2/activity/sleep/${SLEEP_ID}`) return Response.json({ id: SLEEP_ID, cycle_id: 93845 });
			if (url === `${WHOOP_API}/v2/cycle/93845/recovery`) {
				return Response.json({ cycle_id: 93845, sleep_id: SLEEP_ID, score: { recovery_score: 67 } });
			}
			return Response.json({ message: "not found" }, { status: 404 });
		}
		return realFetch(input, init);
	});
});

afterEach(() => {
	vi.restoreAllMocks();
});

function event(overrides: Record<string, unknown> = {}): string {
	traceCounter += 1;
	return JSON.stringify({
		user_id: 555001,
		id: SLEEP_ID,
		type: "sleep.updated",
		trace_id: `trace-${Date.now()}-${traceCounter}`,
		...overrides,
	});
}

async function signedRequest(body: string, options: { timestamp?: number; secret?: string } = {}): Promise<Request> {
	const timestamp = String(options.timestamp ?? Date.now());
	return new Request(`${BASE}/webhooks/whoop`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			"X-WHOOP-Signature-Timestamp": timestamp,
			"X-WHOOP-Signature": await signPayload(options.secret ?? WHOOP_SECRET, timestamp, body),
		},
		body,
	});
}

/** Llama al handler con destinos de reenvío configurados y espera al waitUntil. */
async function deliver(request: Request, overrides: Partial<Env> = {}): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await handleWhoopWebhook(
		request,
		{ ...env, FORWARD_WEBHOOK_URLS: `${RECEIVER_A}, ${RECEIVER_B}`, FORWARD_WEBHOOK_SECRET: FORWARD_SECRET, ...overrides },
		ctx,
	);
	await waitOnExecutionContext(ctx);
	return response;
}

describe("verificación de la firma de WHOOP", () => {
	it("firma válida sin destinos configurados: 204 y no reenvía nada", async () => {
		const response = await exports.default.fetch(await signedRequest(event()));
		expect(response.status).toBe(204);
		expect(delivered).toHaveLength(0);
	});

	it("firma inválida: 401 (también a través del Worker completo)", async () => {
		const response = await exports.default.fetch(await signedRequest(event(), { secret: "otro-secreto" }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "invalid_signature" });
		const forwarded = await deliver(await signedRequest(event(), { secret: "otro-secreto" }));
		expect(forwarded.status).toBe(401);
		expect(delivered).toHaveLength(0);
	});

	it("cuerpo alterado tras firmar: 401", async () => {
		const signed = await signedRequest(event());
		const tampered = new Request(signed, { body: event({ user_id: 1 }) });
		expect((await deliver(tampered)).status).toBe(401);
		expect(delivered).toHaveLength(0);
	});

	it("timestamp de hace más de 5 minutos (bien firmado): 401 stale_timestamp", async () => {
		const response = await deliver(await signedRequest(event(), { timestamp: Date.now() - 6 * 60 * 1000 }));
		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: "stale_timestamp" });
		expect(delivered).toHaveLength(0);
	});

	it("sin cabeceras de firma: 401; GET: 405", async () => {
		const unsigned = new Request(`${BASE}/webhooks/whoop`, { method: "POST", body: event() });
		expect((await exports.default.fetch(unsigned)).status).toBe(401);
		expect((await exports.default.fetch(new Request(`${BASE}/webhooks/whoop`))).status).toBe(405);
	});

	it("verifySignature distingue firma mala, base64 roto y caducada", async () => {
		const body = event();
		const ts = String(Date.now());
		const good = await signPayload(WHOOP_SECRET, ts, body);
		expect(await verifySignature({ secret: WHOOP_SECRET, timestamp: ts, signature: good, rawBody: body })).toBe("ok");
		expect(await verifySignature({ secret: WHOOP_SECRET, timestamp: ts, signature: "%%%", rawBody: body })).toBe("invalid");
		expect(await verifySignature({ secret: WHOOP_SECRET, timestamp: "abc", signature: good, rawBody: body })).toBe("invalid");
		expect(
			await verifySignature({ secret: WHOOP_SECRET, timestamp: ts, signature: good, rawBody: body, now: Number(ts) + 301_000 }),
		).toBe("expired");
	});

	it("evento con forma inválida pero bien firmado: 400", async () => {
		const response = await deliver(await signedRequest(JSON.stringify({ hello: "world" })));
		expect(response.status).toBe(400);
		expect(delivered).toHaveLength(0);
	});
});

describe("reenvío firmado", () => {
	it("reenvía a todos los destinos con firma HMAC propia verificable", async () => {
		const body = event({ type: "workout.updated", id: "0f3e4b3a-9b53-4a3c-8d7e-2f7f0b1a2c3d" });
		const response = await deliver(await signedRequest(body));
		expect(response.status).toBe(204);
		expect(delivered.map((d) => d.url).sort()).toEqual([RECEIVER_A, RECEIVER_B].sort());

		const original = JSON.parse(body);
		for (const d of delivered) {
			const timestamp = d.headers.get(FORWARD_TIMESTAMP_HEADER);
			const signature = d.headers.get(FORWARD_SIGNATURE_HEADER);
			expect(await verifySignature({ secret: FORWARD_SECRET, timestamp, signature, rawBody: d.body })).toBe("ok");
			// Con el secreto de WHOOP NO verifica: son secretos distintos.
			expect(await verifySignature({ secret: WHOOP_SECRET, timestamp, signature, rawBody: d.body })).toBe("invalid");
			expect(d.headers.get(FORWARD_EVENT_HEADER)).toBe("workout.updated");
			expect(d.headers.get(FORWARD_TRACE_HEADER)).toBe(original.trace_id);
			const payload = JSON.parse(d.body);
			expect(payload).toMatchObject({
				version: 1,
				source: "whoop",
				user_id: 555001,
				type: "workout.updated",
				id: original.id,
				trace_id: original.trace_id,
			});
			expect(Date.parse(payload.received_at)).not.toBeNaN();
			expect(payload.recovery).toBeUndefined();
		}
	});

	it("idempotencia por trace_id: el reintento de WHOOP no se reenvía otra vez", async () => {
		const body = event({ type: "sleep.deleted" });
		expect((await deliver(await signedRequest(body))).status).toBe(204);
		expect((await deliver(await signedRequest(body))).status).toBe(204);
		expect(delivered).toHaveLength(2); // 1 evento × 2 destinos
	});

	it("recovery.updated sin token del usuario: solo el evento", async () => {
		const response = await deliver(await signedRequest(event({ type: "recovery.updated", user_id: 555002 })));
		expect(response.status).toBe(204);
		expect(delivered).toHaveLength(2);
		expect(JSON.parse(delivered[0]!.body).recovery).toBeUndefined();
		expect(whoopApiCalls).toHaveLength(0);
	});

	it("recovery.updated con token del usuario: incluye la recuperación resuelta (sueño → ciclo → recuperación)", async () => {
		const namespace = env.WHOOP_TOKEN_VAULT;
		const vault = namespace.get(namespace.idFromName("whoop-user:555003"));
		await vault.storeTokens({ accessToken: "at-555003", refreshToken: "rt", expiresAt: Date.now() + 3_600_000, scope: "offline" }, "555003");

		const response = await deliver(await signedRequest(event({ type: "recovery.updated", user_id: 555003 })));
		expect(response.status).toBe(204);
		expect(whoopApiCalls).toEqual([`${WHOOP_API}/v2/activity/sleep/${SLEEP_ID}`, `${WHOOP_API}/v2/cycle/93845/recovery`]);
		expect(delivered).toHaveLength(2);
		for (const d of delivered) expect(JSON.parse(d.body).recovery.score.recovery_score).toBe(67);
	});

	it("sin FORWARD_WEBHOOK_SECRET no reenvía (nunca sin firmar)", async () => {
		const response = await deliver(await signedRequest(event()), { FORWARD_WEBHOOK_SECRET: undefined });
		expect(response.status).toBe(204);
		expect(delivered).toHaveLength(0);
	});

	it("solo acepta destinos https sin credenciales", () => {
		expect(
			parseForwardUrls(" https://a.example.com/x ,http://b.example.com/y, https://u:p@c.example.com/, nope, https://a.example.com/x"),
		).toEqual(["https://a.example.com/x"]);
		expect(parseForwardUrls(undefined)).toEqual([]);
	});
});
