import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import {
	buildCollectionQuery,
	WHOOP_ENDPOINTS,
	whoopResourcePath,
	WhoopApiError,
	type CollectionParams,
	type WhoopApi,
} from "./whoop/api";
import { WhoopTokenError } from "./whoop/oauth";

// =============================================================================
// Servidor MCP de WHOOP. Todas las tools de DATOS son de solo lectura
// (`readOnlyHint: true`, `openWorldHint: true`: consultan un servicio externo).
// La única excepción es `disconnect_whoop`, que no toca datos: borra la
// conexión (revoca el acceso en WHOOP y los grants MCP del usuario).
// =============================================================================

export const SERVER_NAME = "whoop-mcp";
export const SERVER_VERSION = "0.2.0";

/** Resuelve el cliente de WHOOP del usuario autenticado; lanza si no se puede. */
export type WhoopApiResolver = () => WhoopApi;

/** Desconecta al usuario autenticado (WHOOP + grants MCP). */
export type WhoopDisconnector = () => Promise<{ whoopAccessRevoked: boolean; grantsRevoked: number }>;

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true } as const;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const cycleIdInput = z.object({
	cycleId: z
		.number()
		.int()
		.positive()
		.max(Number.MAX_SAFE_INTEGER)
		.describe("Id numérico del ciclo (campo `id` de get_cycle_collection o `cycle_id` de sueño/recuperación)."),
});

const uuidId = (what: string) =>
	z
		.string()
		.trim()
		.regex(UUID, { message: `Usa el UUID del ${what}.` });

const sleepIdInput = z.object({
	sleepId: uuidId("sueño").describe("UUID del sueño (campo `id` de get_sleep_collection, o `sleep_id` de una recuperación)."),
});

const workoutIdInput = z.object({
	workoutId: uuidId("entreno").describe("UUID del entreno (campo `id` de get_workout_collection)."),
});

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?)?$/;

/** Acepta fecha (YYYY-MM-DD) o fecha-hora ISO 8601. Sin transform: el schema se publica como JSON Schema. */
const isoInstant = z
	.string()
	.trim()
	.refine((value) => ISO_INSTANT.test(value) && !Number.isNaN(Date.parse(value)), {
		message: "Usa una fecha ISO 8601, p. ej. 2026-09-01 o 2026-09-01T06:00:00Z",
	});

/** Normaliza a ISO UTC con milisegundos, el formato que espera WHOOP. */
export function normalizeInstant(value: string | undefined): string | undefined {
	return value === undefined ? undefined : new Date(value.trim()).toISOString();
}

export const collectionInput = z.object({
	start: isoInstant
		.optional()
		.describe("Devuelve registros desde este instante (inclusive). ISO 8601, p. ej. 2026-09-01 o 2026-09-01T00:00:00Z."),
	end: isoInstant.optional().describe("Devuelve registros hasta este instante (exclusivo). ISO 8601. Por defecto, ahora."),
	limit: z.number().int().min(1).max(25).optional().describe("Máximo de registros (1-25). Por defecto 10."),
	nextToken: z.string().trim().min(1).max(512).optional().describe("Token de paginación devuelto en `next_token` por una llamada anterior."),
});

type CollectionInput = z.infer<typeof collectionInput>;

type TextResult = { content: Array<{ type: "text"; text: string }>; isError?: boolean };

function ok(data: unknown): TextResult {
	return { content: [{ type: "text", text: JSON.stringify(data) }] };
}

/** Traduce cualquier fallo a un resultado de tool con isError (nunca filtra tokens). */
export function toolError(error: unknown): TextResult {
	let message: string;
	if (error instanceof WhoopApiError) {
		message =
			error.status === 403
				? "WHOOP denegó el acceso (403): la autorización no incluye el scope necesario. Reconecta WHOOP aceptando todos los permisos."
				: error.message;
	} else if (error instanceof WhoopTokenError) {
		message = error.message;
	} else if (error instanceof Error) {
		message = error.message.replace(/^REAUTH:\s*/, "");
	} else {
		message = "Error inesperado al consultar WHOOP.";
	}
	return { isError: true, content: [{ type: "text", text: message }] };
}

async function run(fn: () => Promise<unknown>): Promise<TextResult> {
	try {
		return ok(await fn());
	} catch (error) {
		return toolError(error);
	}
}

function collection(resolveApi: WhoopApiResolver, endpoint: string, args: CollectionInput): Promise<unknown> {
	const params: CollectionParams = {
		start: normalizeInstant(args.start),
		end: normalizeInstant(args.end),
		limit: args.limit ?? 10,
		nextToken: args.nextToken,
	};
	return resolveApi().get(`${endpoint}${buildCollectionQuery(params)}`);
}

export function createWhoopMcpServer(resolveApi: WhoopApiResolver, disconnect?: WhoopDisconnector): McpServer {
	const server = new McpServer(
		{ name: SERVER_NAME, version: SERVER_VERSION },
		{
			instructions:
				"Datos de WHOOP del usuario conectado, solo lectura. Las colecciones van de más reciente a más antigua y paginan con next_token. " +
				"El strain diario está en get_cycle_collection (score.strain) y el de cada entreno en get_workout_collection. " +
				"Para '¿cómo estoy hoy?' usa get_latest_overview.",
		},
	);

	server.registerTool(
		"get_profile",
		{
			title: "Perfil de WHOOP",
			description: "Perfil básico del usuario de WHOOP autenticado: user_id, nombre y email.",
			annotations: { ...READ_ONLY, title: "Perfil de WHOOP" },
		},
		async () => run(() => resolveApi().get(WHOOP_ENDPOINTS.profile)),
	);

	server.registerTool(
		"get_body_measurement",
		{
			title: "Medidas corporales",
			description: "Medidas corporales registradas en WHOOP: altura (m), peso (kg) y frecuencia cardiaca máxima.",
			annotations: { ...READ_ONLY, title: "Medidas corporales" },
		},
		async () => run(() => resolveApi().get(WHOOP_ENDPOINTS.bodyMeasurement)),
	);

	server.registerTool(
		"get_recovery_collection",
		{
			title: "Recuperación",
			description:
				"Recuperación diaria en un rango de fechas: recovery score (%), HRV (rmssd, ms), frecuencia cardiaca en reposo, SpO2 y temperatura de la piel.",
			inputSchema: collectionInput,
			annotations: { ...READ_ONLY, title: "Recuperación" },
		},
		async (args) => run(() => collection(resolveApi, WHOOP_ENDPOINTS.recovery, args)),
	);

	server.registerTool(
		"get_sleep_collection",
		{
			title: "Sueño",
			description:
				"Registros de sueño (incluye siestas) en un rango de fechas: fases (ligero, profundo/SWS, REM, despierto), duración, frecuencia respiratoria, rendimiento, consistencia y eficiencia.",
			inputSchema: collectionInput,
			annotations: { ...READ_ONLY, title: "Sueño" },
		},
		async (args) => run(() => collection(resolveApi, WHOOP_ENDPOINTS.sleep, args)),
	);

	server.registerTool(
		"get_workout_collection",
		{
			title: "Entrenamientos",
			description:
				"Entrenamientos en un rango de fechas: deporte, strain del entreno, frecuencia cardiaca media y máxima, kilojulios, distancia y tiempo por zonas de FC.",
			inputSchema: collectionInput,
			annotations: { ...READ_ONLY, title: "Entrenamientos" },
		},
		async (args) => run(() => collection(resolveApi, WHOOP_ENDPOINTS.workout, args)),
	);

	server.registerTool(
		"get_cycle_collection",
		{
			title: "Ciclos y strain diario",
			description:
				"Ciclos fisiológicos (días de WHOOP) en un rango de fechas: strain del día, kilojulios, frecuencia cardiaca media y máxima. Un ciclo sin `end` es el día en curso.",
			inputSchema: collectionInput,
			annotations: { ...READ_ONLY, title: "Ciclos y strain diario" },
		},
		async (args) => run(() => collection(resolveApi, WHOOP_ENDPOINTS.cycle, args)),
	);

	server.registerTool(
		"get_cycle",
		{
			title: "Ciclo por id",
			description: "Un ciclo fisiológico (día de WHOOP) por su id: inicio, fin, strain, kilojulios y frecuencia cardiaca media y máxima.",
			inputSchema: cycleIdInput,
			annotations: { ...READ_ONLY, title: "Ciclo por id" },
		},
		async (args) => run(() => resolveApi().get(whoopResourcePath.cycle(args.cycleId))),
	);

	server.registerTool(
		"get_cycle_sleep",
		{
			title: "Sueño de un ciclo",
			description: "El sueño principal asociado a un ciclo: fases, duración, rendimiento, eficiencia y frecuencia respiratoria.",
			inputSchema: cycleIdInput,
			annotations: { ...READ_ONLY, title: "Sueño de un ciclo" },
		},
		async (args) => run(() => resolveApi().get(whoopResourcePath.cycleSleep(args.cycleId))),
	);

	server.registerTool(
		"get_cycle_recovery",
		{
			title: "Recuperación de un ciclo",
			description: "La recuperación de un ciclo: recovery score (%), HRV (rmssd, ms), frecuencia cardiaca en reposo, SpO2 y temperatura de la piel.",
			inputSchema: cycleIdInput,
			annotations: { ...READ_ONLY, title: "Recuperación de un ciclo" },
		},
		async (args) => run(() => resolveApi().get(whoopResourcePath.cycleRecovery(args.cycleId))),
	);

	server.registerTool(
		"get_sleep",
		{
			title: "Sueño por id",
			description: "Un registro de sueño (o siesta) por su UUID: fases, duración, rendimiento, consistencia y eficiencia.",
			inputSchema: sleepIdInput,
			annotations: { ...READ_ONLY, title: "Sueño por id" },
		},
		async (args) => run(() => resolveApi().get(whoopResourcePath.sleep(args.sleepId))),
	);

	server.registerTool(
		"get_workout",
		{
			title: "Entreno por id",
			description: "Un entrenamiento por su UUID: deporte, strain, frecuencia cardiaca media y máxima, kilojulios, distancia y zonas de FC.",
			inputSchema: workoutIdInput,
			annotations: { ...READ_ONLY, title: "Entreno por id" },
		},
		async (args) => run(() => resolveApi().get(whoopResourcePath.workout(args.workoutId))),
	);

	if (disconnect) {
		server.registerTool(
			"disconnect_whoop",
			{
				title: "Desconectar WHOOP",
				description:
					"Desconecta la cuenta de WHOOP de este servidor: revoca el acceso de la app en WHOOP, borra el token guardado y " +
					"revoca las sesiones MCP del usuario (hará falta volver a conectar). No borra datos en WHOOP. " +
					"Úsala SOLO cuando el usuario lo pida explícitamente.",
				inputSchema: z.object({
					confirm: z.literal(true).describe("Debe ser true: confirma que el usuario pidió desconectar."),
				}),
				annotations: {
					title: "Desconectar WHOOP",
					readOnlyHint: false,
					destructiveHint: true,
					idempotentHint: true,
					openWorldHint: true,
				},
			},
			async () =>
				run(async () => {
					const result = await disconnect();
					return {
						disconnected: true,
						whoop_access_revoked: result.whoopAccessRevoked,
						mcp_grants_revoked: result.grantsRevoked,
					};
				}),
		);
	}

	server.registerTool(
		"get_latest_overview",
		{
			title: "Resumen más reciente",
			description:
				"Resumen de un vistazo: el ciclo más reciente (strain del día), la última recuperación y el último sueño. Útil para '¿cómo estoy hoy?'.",
			annotations: { ...READ_ONLY, title: "Resumen más reciente" },
		},
		async () =>
			run(async () => {
				const api = resolveApi();
				const one = (endpoint: string) => api.get<{ records?: unknown[] }>(`${endpoint}?limit=1`);
				const [cycle, recovery, sleep] = await Promise.allSettled([
					one(WHOOP_ENDPOINTS.cycle),
					one(WHOOP_ENDPOINTS.recovery),
					one(WHOOP_ENDPOINTS.sleep),
				]);
				const failures = [cycle, recovery, sleep].filter((r) => r.status === "rejected");
				if (failures.length === 3) throw (failures[0] as PromiseRejectedResult).reason;
				const pick = (result: PromiseSettledResult<{ records?: unknown[] }>) =>
					result.status === "fulfilled"
						? (result.value.records?.[0] ?? null)
						: { error: toolError(result.reason).content[0]?.text };
				return {
					latest_cycle: pick(cycle),
					latest_recovery: pick(recovery),
					latest_sleep: pick(sleep),
				};
			}),
	);

	return server;
}
