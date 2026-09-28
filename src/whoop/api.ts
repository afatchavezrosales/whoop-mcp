// =============================================================================
// Cliente HTTP de la API v2 de WHOOP (solo GET para los datos; la única
// escritura es DELETE /v2/user/access al desconectar, ver revokeWhoopAccess).
// Referencia: https://developer.whoop.com/api
// =============================================================================

export const WHOOP_API_BASE_URL = "https://api.prod.whoop.com/developer";

export const WHOOP_ENDPOINTS = {
	profile: "/v2/user/profile/basic",
	bodyMeasurement: "/v2/user/measurement/body",
	recovery: "/v2/recovery",
	sleep: "/v2/activity/sleep",
	workout: "/v2/activity/workout",
	cycle: "/v2/cycle",
	userAccess: "/v2/user/access",
} as const;

/** Rutas de un recurso concreto. Los ids se validan en las tools y aquí se codifican igualmente. */
export const whoopResourcePath = {
	cycle: (cycleId: number) => `${WHOOP_ENDPOINTS.cycle}/${encodeURIComponent(String(cycleId))}`,
	cycleSleep: (cycleId: number) => `${WHOOP_ENDPOINTS.cycle}/${encodeURIComponent(String(cycleId))}/sleep`,
	cycleRecovery: (cycleId: number) => `${WHOOP_ENDPOINTS.cycle}/${encodeURIComponent(String(cycleId))}/recovery`,
	sleep: (sleepId: string) => `${WHOOP_ENDPOINTS.sleep}/${encodeURIComponent(sleepId)}`,
	workout: (workoutId: string) => `${WHOOP_ENDPOINTS.workout}/${encodeURIComponent(workoutId)}`,
} as const;

const REQUEST_TIMEOUT_MS = 20_000;
const MAX_RATE_LIMIT_RETRIES = 2;
const BASE_RETRY_DELAY_MS = 1_000;
/** Tope al Retry-After que imponga WHOOP: no bloquear la tool más de 5 s por intento. */
const MAX_RETRY_DELAY_MS = 5_000;
const MAX_ERROR_BODY_CHARS = 500;

export class WhoopApiError extends Error {
	override readonly name = "WhoopApiError";
	constructor(
		readonly status: number,
		readonly detail: string,
	) {
		super(`La API de WHOOP respondió ${status}${detail ? `: ${detail}` : ""}`);
	}
}

/** Proveedor de tokens: sin argumento, uno válido; con el token rechazado, fuerza refresh. */
export type AccessTokenProvider = (rejectedToken?: string) => Promise<string>;

export interface CollectionParams {
	start?: string;
	end?: string;
	limit?: number;
	nextToken?: string;
}

export function buildCollectionQuery(params: CollectionParams): string {
	const search = new URLSearchParams();
	if (params.start !== undefined) search.set("start", params.start);
	if (params.end !== undefined) search.set("end", params.end);
	if (params.limit !== undefined) search.set("limit", String(params.limit));
	if (params.nextToken !== undefined) search.set("nextToken", params.nextToken);
	const query = search.toString();
	return query ? `?${query}` : "";
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

function retryDelay(response: Response, attempt: number): number {
	const header = response.headers.get("retry-after");
	const seconds = header === null ? Number.NaN : Number(header);
	const ms = Number.isFinite(seconds) && seconds >= 0 ? seconds * 1000 : BASE_RETRY_DELAY_MS * 2 ** attempt;
	return Math.min(ms, MAX_RETRY_DELAY_MS);
}

async function errorDetail(response: Response): Promise<string> {
	let text = "";
	try {
		text = await response.text();
	} catch {
		return response.statusText;
	}
	return (text || response.statusText).slice(0, MAX_ERROR_BODY_CHARS);
}

export interface WhoopApi {
	get<T>(path: string): Promise<T>;
}

export function createWhoopApi(options: {
	getAccessToken: AccessTokenProvider;
	fetchImpl?: typeof fetch;
	baseUrl?: string;
}): WhoopApi {
	const fetchImpl = options.fetchImpl ?? fetch;
	const baseUrl = options.baseUrl ?? WHOOP_API_BASE_URL;

	async function send(url: string, token: string): Promise<Response> {
		try {
			return await fetchImpl(url, {
				method: "GET",
				headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
				signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
			});
		} catch (error) {
			throw new WhoopApiError(0, `no se pudo contactar con WHOOP (${error instanceof Error ? error.message : "error de red"})`);
		}
	}

	return {
		async get<T>(path: string): Promise<T> {
			const url = `${baseUrl}${path}`;
			let token = await options.getAccessToken();
			let refreshedOnce = false;

			for (let attempt = 0; ; attempt++) {
				const response = await send(url, token);
				if (response.ok) return (await response.json()) as T;

				if (response.status === 401 && !refreshedOnce) {
					// El token pudo invalidarse antes de su expires_in: forzar refresh una vez.
					await response.body?.cancel();
					refreshedOnce = true;
					token = await options.getAccessToken(token);
					continue;
				}

				if (response.status === 429 && attempt < MAX_RATE_LIMIT_RETRIES) {
					const delay = retryDelay(response, attempt);
					await response.body?.cancel();
					await sleep(delay);
					continue;
				}

				throw new WhoopApiError(response.status, await errorDetail(response));
			}
		},
	};
}

/**
 * DELETE /v2/user/access: revoca el acceso de ESTA app de WHOOP a la cuenta del
 * usuario (todas sus conexiones y sus webhooks). WHOOP responde 204.
 * Devuelve el status HTTP (0 = error de red); nunca lanza.
 */
export async function revokeWhoopAccess(
	accessToken: string,
	options: { fetchImpl?: typeof fetch; baseUrl?: string } = {},
): Promise<number> {
	const fetchImpl = options.fetchImpl ?? fetch;
	const baseUrl = options.baseUrl ?? WHOOP_API_BASE_URL;
	try {
		const response = await fetchImpl(`${baseUrl}${WHOOP_ENDPOINTS.userAccess}`, {
			method: "DELETE",
			headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
			signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
		});
		await response.body?.cancel();
		return response.status;
	} catch {
		return 0;
	}
}
