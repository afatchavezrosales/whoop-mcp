import { vaultFor } from "./token-vault";
import { createWhoopApi, whoopResourcePath } from "./whoop/api";
import { whoopCredentials } from "./whoop/oauth";

// =============================================================================
// Webhooks de WHOOP (modelo v2) → reenvío firmado a destinos configurables.
//
//   WHOOP ──POST /webhooks/whoop──▶ Worker ──POST firmado──▶ FORWARD_WEBHOOK_URLS
//
// 1. Verifica X-WHOOP-Signature = base64(HMAC-SHA256(timestamp + raw_body,
//    WHOOP_CLIENT_SECRET)) con X-WHOOP-Signature-Timestamp (ms desde epoch),
//    en tiempo constante (crypto.subtle.verify) y con ventana de ±5 minutos.
// 2. Responde 204 enseguida: el reenvío va en ctx.waitUntil, así WHOOP no
//    reintenta por culpa de un destino lento.
// 3. Idempotencia best-effort por trace_id (KV con TTL corto): los reintentos
//    de WHOOP del mismo evento no se reenvían dos veces.
// 4. Reenvía a cada destino un JSON propio firmado con FORWARD_WEBHOOK_SECRET
//    (cabeceras X-Whoop-MCP-*). Para recovery.updated añade, si el usuario tiene
//    un token guardado, la recuperación ya resuelta.
//
// Referencia: https://developer.whoop.com/docs/developing/webhooks
// =============================================================================

export const WHOOP_WEBHOOK_PATH = "/webhooks/whoop";

export const WHOOP_SIGNATURE_HEADER = "X-WHOOP-Signature";
export const WHOOP_TIMESTAMP_HEADER = "X-WHOOP-Signature-Timestamp";

export const FORWARD_SIGNATURE_HEADER = "X-Whoop-MCP-Signature";
export const FORWARD_TIMESTAMP_HEADER = "X-Whoop-MCP-Signature-Timestamp";
export const FORWARD_EVENT_HEADER = "X-Whoop-MCP-Event";
export const FORWARD_TRACE_HEADER = "X-Whoop-MCP-Trace-Id";
export const FORWARD_PAYLOAD_VERSION = 1;

/** Ventana de validez del timestamp firmado. */
export const MAX_TIMESTAMP_SKEW_MS = 5 * 60 * 1000;
const MAX_BODY_BYTES = 64 * 1024;
const DEDUP_PREFIX = "whoop-webhook-trace:";
const DEDUP_TTL_SECONDS = 60 * 60;
const MAX_FORWARD_URLS = 10;
const FORWARD_TIMEOUT_MS = 8_000;
const FORWARD_RETRY_DELAYS_MS = [0, 1_000, 3_000];
const RESOLVE_TIMEOUT_MS = 12_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT_TYPE = /^[a-z_]{1,40}\.[a-z_]{1,40}$/;
const TRACE_ID = /^[A-Za-z0-9._:-]{1,200}$/;

export interface WhoopWebhookEvent {
	user_id: number;
	/** UUID del recurso (en recovery.*, el UUID del sueño asociado). */
	id: string;
	type: string;
	trace_id: string;
}

export interface ForwardedWebhook extends WhoopWebhookEvent {
	version: typeof FORWARD_PAYLOAD_VERSION;
	source: "whoop";
	/** Instante (ISO 8601) en que el Worker recibió y verificó el evento. */
	received_at: string;
	/** Solo en recovery.updated y solo si el usuario tiene un token guardado. */
	recovery?: unknown;
}

export type SignatureCheck = "ok" | "invalid" | "expired";

const encoder = new TextEncoder();

function hmacKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
	return crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

function toBase64(bytes: Uint8Array): string {
	let binary = "";
	for (const b of bytes) binary += String.fromCharCode(b);
	return btoa(binary);
}

function fromBase64(value: string): Uint8Array | null {
	try {
		const binary = atob(value.trim());
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
		return bytes;
	} catch {
		return null;
	}
}

/** base64(HMAC-SHA256(message, secret)) — el esquema de WHOOP y el de nuestro reenvío. */
export async function signPayload(secret: string, timestamp: string, rawBody: string): Promise<string> {
	const key = await hmacKey(secret, "sign");
	const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(timestamp + rawBody));
	return toBase64(new Uint8Array(mac));
}

/**
 * Verifica una firma estilo WHOOP. `crypto.subtle.verify` compara en tiempo
 * constante. El timestamp (ms desde epoch) debe estar a menos de 5 minutos.
 */
export async function verifySignature(params: {
	secret: string;
	timestamp: string | null;
	signature: string | null;
	rawBody: string;
	now?: number;
}): Promise<SignatureCheck> {
	const { secret, timestamp, signature, rawBody } = params;
	if (!timestamp || !signature || !/^\d{1,16}$/.test(timestamp)) return "invalid";
	const signatureBytes = fromBase64(signature);
	if (!signatureBytes || signatureBytes.length !== 32) return "invalid";
	const key = await hmacKey(secret, "verify");
	const valid = await crypto.subtle.verify("HMAC", key, signatureBytes, encoder.encode(timestamp + rawBody));
	if (!valid) return "invalid";
	const now = params.now ?? Date.now();
	return Math.abs(now - Number(timestamp)) > MAX_TIMESTAMP_SKEW_MS ? "expired" : "ok";
}

/** Valida la forma del evento de WHOOP v2. */
export function parseWhoopEvent(rawBody: string): WhoopWebhookEvent | null {
	let json: unknown;
	try {
		json = JSON.parse(rawBody);
	} catch {
		return null;
	}
	if (!json || typeof json !== "object" || Array.isArray(json)) return null;
	const raw = json as Record<string, unknown>;
	const userId =
		typeof raw.user_id === "number"
			? raw.user_id
			: typeof raw.user_id === "string" && /^\d{1,16}$/.test(raw.user_id)
				? Number(raw.user_id)
				: Number.NaN;
	if (!Number.isSafeInteger(userId) || userId <= 0) return null;
	const id = typeof raw.id === "string" || typeof raw.id === "number" ? String(raw.id) : "";
	if (id.length === 0 || id.length > 100) return null;
	if (typeof raw.type !== "string" || !EVENT_TYPE.test(raw.type)) return null;
	if (typeof raw.trace_id !== "string" || !TRACE_ID.test(raw.trace_id)) return null;
	return { user_id: userId, id, type: raw.type, trace_id: raw.trace_id };
}

/** Destinos de FORWARD_WEBHOOK_URLS: solo https, sin credenciales, sin duplicados. */
export function parseForwardUrls(value: string | undefined): string[] {
	if (!value) return [];
	const urls = new Set<string>();
	for (const entry of value.split(",")) {
		const candidate = entry.trim();
		if (!candidate) continue;
		let url: URL;
		try {
			url = new URL(candidate);
		} catch {
			console.warn("FORWARD_WEBHOOK_URLS: se ignora una entrada que no es una URL.");
			continue;
		}
		if (url.protocol !== "https:" || url.username || url.password) {
			console.warn(`FORWARD_WEBHOOK_URLS: se ignora ${url.host} (solo https y sin credenciales en la URL).`);
			continue;
		}
		urls.add(url.href);
	}
	return [...urls].slice(0, MAX_FORWARD_URLS);
}

function jsonError(status: number, error: string, headers: Record<string, string> = {}): Response {
	return Response.json({ error }, { status, headers: { "Cache-Control": "no-store", ...headers } });
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => reject(new Error("timeout")), ms);
		promise.then(
			(value) => {
				clearTimeout(timer);
				resolve(value);
			},
			(error) => {
				clearTimeout(timer);
				reject(error);
			},
		);
	});
}

/**
 * Para recovery.updated: resuelve la recuperación con el token del usuario, si
 * lo tenemos. En v2 el `id` del evento es el UUID del sueño: sueño → cycle_id →
 * recuperación del ciclo. Cualquier fallo devuelve undefined (se reenvía el
 * evento sin enriquecer).
 */
export async function resolveRecovery(env: Env, event: WhoopWebhookEvent): Promise<unknown> {
	if (event.type !== "recovery.updated" || !UUID.test(event.id) || !whoopCredentials(env)) return undefined;
	try {
		const vault = vaultFor(env, String(event.user_id));
		if ((await vault.status()) !== "connected") return undefined;
		const api = createWhoopApi({ getAccessToken: (rejected) => vault.getAccessToken(rejected) });
		return await withTimeout(
			(async () => {
				const sleepRecord = await api.get<{ cycle_id?: unknown }>(whoopResourcePath.sleep(event.id));
				const cycleId = sleepRecord.cycle_id;
				if (typeof cycleId !== "number" || !Number.isSafeInteger(cycleId)) return undefined;
				return await api.get<unknown>(whoopResourcePath.cycleRecovery(cycleId));
			})(),
			RESOLVE_TIMEOUT_MS,
		);
	} catch (error) {
		console.warn("Webhook: no se pudo resolver la recuperación:", error instanceof Error ? error.message : "error");
		return undefined;
	}
}

async function deliver(url: string, body: string, headers: Record<string, string>): Promise<boolean> {
	const host = new URL(url).host;
	for (const [attempt, delay] of FORWARD_RETRY_DELAYS_MS.entries()) {
		if (delay > 0) await sleep(delay);
		try {
			const response = await fetch(url, {
				method: "POST",
				headers,
				body,
				redirect: "manual",
				signal: AbortSignal.timeout(FORWARD_TIMEOUT_MS),
			});
			await response.body?.cancel();
			if (response.ok) return true;
			const retryable = response.status >= 500 || response.status === 408 || response.status === 429;
			console.warn(`Webhook: ${host} respondió ${response.status} (intento ${attempt + 1}).`);
			if (!retryable) return false;
		} catch (error) {
			console.warn(`Webhook: ${host} no responde (intento ${attempt + 1}):`, error instanceof Error ? error.message : "error");
		}
	}
	return false;
}

/** Construye, firma y reenvía el evento a todos los destinos. */
export async function forwardEvent(
	env: Env,
	event: WhoopWebhookEvent,
	urls: string[],
	secret: string,
	receivedAt: Date,
): Promise<void> {
	const payload: ForwardedWebhook = {
		version: FORWARD_PAYLOAD_VERSION,
		source: "whoop",
		user_id: event.user_id,
		type: event.type,
		id: event.id,
		trace_id: event.trace_id,
		received_at: receivedAt.toISOString(),
	};
	const recovery = await resolveRecovery(env, event);
	if (recovery !== undefined) payload.recovery = recovery;

	const body = JSON.stringify(payload);
	const timestamp = String(Date.now());
	const headers = {
		"Content-Type": "application/json",
		"User-Agent": "whoop-mcp-webhook-forwarder",
		[FORWARD_TIMESTAMP_HEADER]: timestamp,
		[FORWARD_SIGNATURE_HEADER]: await signPayload(secret, timestamp, body),
		[FORWARD_EVENT_HEADER]: event.type,
		[FORWARD_TRACE_HEADER]: event.trace_id,
	};
	await Promise.allSettled(urls.map((url) => deliver(url, body, headers)));
}

async function readBody(request: Request): Promise<string | null> {
	const declared = Number(request.headers.get("Content-Length") ?? "0");
	if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) return null;
	const buffer = await request.arrayBuffer();
	if (buffer.byteLength > MAX_BODY_BYTES) return null;
	return new TextDecoder().decode(buffer);
}

/** POST /webhooks/whoop */
export async function handleWhoopWebhook(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	if (request.method !== "POST") return jsonError(405, "method_not_allowed", { Allow: "POST" });

	// Sin cabeceras de firma bien formadas no hay nada que verificar: 401 antes de mirar la configuración.
	const timestampHeader = request.headers.get(WHOOP_TIMESTAMP_HEADER);
	const signatureHeader = request.headers.get(WHOOP_SIGNATURE_HEADER);
	if (!timestampHeader || !/^\d{1,16}$/.test(timestampHeader) || fromBase64(signatureHeader ?? "")?.length !== 32) {
		return jsonError(401, "invalid_signature");
	}

	const credentials = whoopCredentials(env);
	if (!credentials) return jsonError(503, "whoop_not_configured");

	const rawBody = await readBody(request);
	if (rawBody === null) return jsonError(413, "payload_too_large");

	const check = await verifySignature({
		secret: credentials.clientSecret,
		timestamp: timestampHeader,
		signature: signatureHeader,
		rawBody,
	});
	if (check === "invalid") return jsonError(401, "invalid_signature");
	if (check === "expired") return jsonError(401, "stale_timestamp");

	const event = parseWhoopEvent(rawBody);
	if (!event) return jsonError(400, "invalid_event");

	const urls = parseForwardUrls(env.FORWARD_WEBHOOK_URLS);
	if (urls.length === 0) return new Response(null, { status: 204 });

	const forwardSecret = env.FORWARD_WEBHOOK_SECRET?.trim();
	if (!forwardSecret || forwardSecret.length < 32) {
		console.error("Webhook: hay FORWARD_WEBHOOK_URLS pero falta FORWARD_WEBHOOK_SECRET (32+ caracteres); no se reenvía.");
		return new Response(null, { status: 204 });
	}

	// Idempotencia best-effort (KV es eventualmente consistente entre regiones).
	const dedupKey = `${DEDUP_PREFIX}${event.trace_id}`;
	try {
		if (await env.OAUTH_KV.get(dedupKey)) return new Response(null, { status: 204 });
		await env.OAUTH_KV.put(dedupKey, "1", { expirationTtl: DEDUP_TTL_SECONDS });
	} catch (error) {
		console.warn("Webhook: KV no disponible para deduplicar:", error instanceof Error ? error.message : "error");
	}

	ctx.waitUntil(
		forwardEvent(env, event, urls, forwardSecret, new Date()).catch((error) => {
			console.error("Webhook: fallo al reenviar:", error instanceof Error ? error.message : "error");
		}),
	);
	return new Response(null, { status: 204 });
}
