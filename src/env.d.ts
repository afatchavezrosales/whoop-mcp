// Secretos del Worker (no aparecen en wrangler.jsonc, así que `wrangler types`
// no los genera). Opcionales a propósito: el Worker debe arrancar sin ellos y
// responder con un error claro. Se fusionan con la base que genera wrangler,
// de la que heredan tanto `Env` como `Cloudflare.Env`.
interface __BaseEnv_Env {
	WHOOP_CLIENT_ID?: string;
	WHOOP_CLIENT_SECRET?: string;
	/** 32+ caracteres; firma la cookie de "consentimiento recordado". */
	CONSENT_SECRET?: string;
	/** Destinos del reenvío de webhooks de WHOOP, separados por comas (solo https). */
	FORWARD_WEBHOOK_URLS?: string;
	/** 32+ caracteres; firma (HMAC-SHA256) los webhooks reenviados. */
	FORWARD_WEBHOOK_SECRET?: string;
}
