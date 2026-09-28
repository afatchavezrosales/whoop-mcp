// =============================================================================
// Icono del servidor MCP (spec MCP 2025-11: `Implementation.icons`).
//
// Es un icono GENÉRICO de pulso dentro de un corazón, no el logotipo de WHOOP:
// la marca WHOOP es de WHOOP, Inc. y este proyecto no está afiliado ni avalado
// por ellos, así que no se reproduce su logotipo ni su wordmark. Los clientes
// MCP ya muestran el nombre del servidor al lado.
//
// Se sirve desde el propio Worker (GET /icon.svg), sin dependencias externas,
// y se anuncia en `serverInfo.icons` con la URL absoluta de PUBLIC_BASE_URL.
// El SVG no lleva scripts ni referencias externas; aun así va con CSP
// `default-src 'none'` y nosniff por si alguien lo abre como documento.
// =============================================================================

export const ICON_PATH = "/icon.svg";

export const ICON_SVG =
	'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">' +
	'<rect width="64" height="64" rx="14" fill="#111111"/>' +
	'<path d="M32 50 C20 41 12 34 12 25 C12 19 16.5 15 22 15 C26 15 29.6 17.3 32 20.6 C34.4 17.3 38 15 42 15 C47.5 15 52 19 52 25 C52 34 44 41 32 50 Z" ' +
	'fill="none" stroke="#FFFFFF" stroke-opacity="0.35" stroke-width="3" stroke-linejoin="round"/>' +
	'<path d="M10 33 H22 L26 25 L31 41 L36 29 L39 33 H54" fill="none" stroke="#FFFFFF" stroke-width="3.5" ' +
	'stroke-linecap="round" stroke-linejoin="round"/>' +
	"</svg>";

export interface McpIcon {
	src: string;
	mimeType: string;
	sizes: string[];
}

/** `icons` del serverInfo: el SVG del Worker, en URL absoluta (los clientes lo piden desde fuera). */
export function serverIcons(publicBaseUrl: string | undefined): McpIcon[] | undefined {
	const base = String(publicBaseUrl ?? "").replace(/\/+$/, "");
	if (!/^https:\/\/[^/]+/.test(base)) return undefined;
	return [{ src: `${base}${ICON_PATH}`, mimeType: "image/svg+xml", sizes: ["any"] }];
}

/** Respuesta de GET/HEAD /icon.svg. */
export function iconResponse(request: Request): Response {
	if (request.method !== "GET" && request.method !== "HEAD") {
		return new Response("Method not allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
	}
	return new Response(request.method === "HEAD" ? null : ICON_SVG, {
		headers: {
			"Content-Type": "image/svg+xml; charset=utf-8",
			"Cache-Control": "public, max-age=86400",
			"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
			"X-Content-Type-Options": "nosniff",
			// Se incrusta desde otros orígenes (el cliente MCP lo pinta en su UI).
			"Cross-Origin-Resource-Policy": "cross-origin",
		},
	});
}
