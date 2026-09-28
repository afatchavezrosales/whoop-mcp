import type { ConsentDescription } from "@cloudflare/workers-oauth-provider";

// Páginas HTML mínimas (consentimiento y errores). TODO lo que viene del
// cliente OAuth (nombre, dominio, redirect, scopes) es controlado por un
// atacante potencial (DCR/CIMD): se escapa SIEMPRE.

export function escapeHtml(value: string): string {
	return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

const CSP =
	"default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; frame-ancestors 'none'; base-uri 'none'";

const STYLE = `
:root{color-scheme:light dark;--bg:#f6f6f4;--card:#fff;--text:#18181b;--muted:#63636b;--line:#e4e4e7;--accent:#0080ff;--warn:#b45309}
@media (prefers-color-scheme:dark){:root{--bg:#111113;--card:#18181b;--text:#f4f4f5;--muted:#a1a1aa;--line:#2e2e33;--warn:#f59e0b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:400 15px/1.55 -apple-system,BlinkMacSystemFont,"Inter","Segoe UI",Roboto,sans-serif}
main{max-width:520px;margin:48px auto;padding:0 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px}
h1{font-size:21px;font-weight:500;margin:0 0 12px;line-height:1.3}
p{margin:0 0 12px;color:var(--muted)}
p strong{color:var(--text);font-weight:500}
ul{margin:0 0 16px;padding-left:18px;color:var(--muted)}
.warn{color:var(--warn)}
.actions{display:flex;gap:10px;justify-content:flex-end;margin-top:20px;flex-wrap:wrap}
button{font:inherit;border-radius:10px;padding:10px 18px;cursor:pointer;border:1px solid var(--line);background:transparent;color:var(--text)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
code{font-size:13px}
`;

function page(title: string, body: string): string {
	return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main><div class="card">${body}</div></main></body></html>`;
}

function htmlHeaders(base?: Headers): Headers {
	const headers = base ?? new Headers();
	headers.set("Content-Type", "text/html; charset=utf-8");
	headers.set("Content-Security-Policy", CSP);
	headers.set("X-Frame-Options", "DENY");
	headers.set("X-Content-Type-Options", "nosniff");
	headers.set("Referrer-Policy", "no-referrer");
	headers.set("Cache-Control", "no-store");
	return headers;
}

export function renderConsentPage(details: ConsentDescription, handle: string, headers: Headers): Response {
	const name = escapeHtml(details.clientName);
	const origin = details.clientDomain
		? `Publicada por <strong>${escapeHtml(details.clientDomain)}</strong>.`
		: "Esta aplicación se registró sola: su nombre no está verificado.";
	const loopback = details.redirectIsLoopback
		? `<p class="warn">El acceso se enviará a una aplicación de este ordenador. Continúa solo si acabas de iniciar la conexión desde ella.</p>`
		: "";
	const body = `
<h1>¿Permitir que ${name} lea tus datos de WHOOP?</h1>
<p>${origin} El acceso se enviará a <strong>${escapeHtml(details.redirectHost)}</strong>.</p>
${loopback}
<p>Si aceptas, iniciarás sesión en WHOOP y ${name} podrá <strong>leer</strong> (nunca modificar):</p>
<ul><li>Perfil y medidas corporales</li><li>Recuperación, HRV y frecuencia cardiaca en reposo</li><li>Sueño</li><li>Ciclos diarios y strain</li><li>Entrenamientos</li></ul>
<form method="post" action="/authorize">
<input type="hidden" name="handle" value="${escapeHtml(handle)}">
<div class="actions"><button type="submit" name="decision" value="deny">Cancelar</button><button class="primary" type="submit" name="decision" value="approve">Continuar con WHOOP</button></div>
</form>`;
	return new Response(page(`Autorizar ${details.clientName}`, body), { status: 200, headers: htmlHeaders(headers) });
}

export function renderErrorPage(status: number, title: string, message: string, headers?: Headers): Response {
	const body = `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`;
	return new Response(page(title, body), { status, headers: htmlHeaders(headers) });
}
