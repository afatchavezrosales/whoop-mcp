import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

// Dos proyectos sobre el mismo wrangler.jsonc:
//  - "unconfigured": sin secretos de WHOOP, como está desplegado hasta que el
//    usuario los ponga (el Worker debe responder con un error claro).
//  - "configured": con credenciales FALSAS de WHOOP para probar el vault y el
//    flujo; ninguna petición sale a WHOOP (fetch se mockea en cada test).
export default defineConfig({
	test: {
		projects: [
			{
				plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
				test: { name: "unconfigured", include: ["test/unconfigured/**/*.test.ts"] },
			},
			{
				plugins: [
					cloudflareTest({
						wrangler: { configPath: "./wrangler.jsonc" },
						miniflare: {
							bindings: {
								WHOOP_CLIENT_ID: "test-client-id",
								WHOOP_CLIENT_SECRET: "test-client-secret",
								CONSENT_SECRET: "test-consent-secret-with-at-least-32-chars",
							},
						},
					}),
				],
				test: { name: "configured", include: ["test/configured/**/*.test.ts"] },
			},
		],
	},
});
