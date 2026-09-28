# whoop-mcp

A remote [MCP](https://modelcontextprotocol.io) server for [WHOOP](https://www.whoop.com), running on
Cloudflare Workers. Any MCP client (Claude, ChatGPT, your own agent) connects over Streamable HTTP,
signs in with WHOOP through OAuth 2.1, and gets read-only tools over the user's recovery, sleep,
strain and workouts. It can also receive WHOOP webhooks and forward them, signed, to your own
endpoints.

- **OAuth 2.1 authorization server** for MCP clients (PKCE S256, Dynamic Client Registration,
  Client ID Metadata Documents, RFC 8414 / RFC 9728 metadata, RFC 7009 revocation), built on
  [`@cloudflare/workers-oauth-provider`](https://github.com/cloudflare/workers-oauth-provider).
- **Read-only data tools** (`readOnlyHint: true`) against the WHOOP API v2.
- **WHOOP tokens never reach the MCP client**: they live in a per-user Durable Object.
- **Signed webhooks**: WHOOP v2 events are verified and re-signed before forwarding.

## Tools

| Tool | WHOOP endpoint | Notes |
| --- | --- | --- |
| `get_profile` | `GET /v2/user/profile/basic` | user id, name, email |
| `get_body_measurement` | `GET /v2/user/measurement/body` | height, weight, max heart rate |
| `get_recovery_collection` | `GET /v2/recovery` | `start`, `end`, `limit` (1-25), `nextToken` |
| `get_sleep_collection` | `GET /v2/activity/sleep` | same pagination |
| `get_workout_collection` | `GET /v2/activity/workout` | same pagination |
| `get_cycle_collection` | `GET /v2/cycle` | same pagination; daily strain |
| `get_latest_overview` | cycle + recovery + sleep | latest of each, in one call |
| `get_cycle` | `GET /v2/cycle/{cycleId}` | `cycleId` (integer) |
| `get_cycle_sleep` | `GET /v2/cycle/{cycleId}/sleep` | `cycleId` (integer) |
| `get_cycle_recovery` | `GET /v2/cycle/{cycleId}/recovery` | `cycleId` (integer) |
| `get_sleep` | `GET /v2/activity/sleep/{sleepId}` | `sleepId` (UUID) |
| `get_workout` | `GET /v2/activity/workout/{workoutId}` | `workoutId` (UUID) |
| `disconnect_whoop` | `DELETE /v2/user/access` | **not read-only** (`destructiveHint: true`), requires `confirm: true`; see [Disconnecting](#disconnecting-and-revocation) |

Every data tool is annotated `readOnlyHint: true`. Ids are validated before any request is made.
The user-facing strings (tool descriptions, consent page) are currently in Spanish.

## Architecture

```
MCP client ──OAuth 2.1 + PKCE──▶ Worker (authorization server + /mcp) ──OAuth 2.0──▶ WHOOP
                                   │
                                   ├── KV  OAUTH_KV          clients, grants, token hashes, encrypted props
                                   └── DO  WhoopTokenVault   one object per WHOOP user: WHOOP access/refresh token
WHOOP ──POST /webhooks/whoop──▶ Worker ──signed POST──▶ FORWARD_WEBHOOK_URLS
```

- `src/index.ts`: the `OAuthProvider` (authorization server + protected resource `/mcp`), the MCP
  handler (`createMcpHandler` from `agents`), the RFC 7009 revocation hook, and the webhook and
  disconnect routes.
- `src/auth-handler.ts`: `/authorize` shows a per-client consent page (confused-deputy protection),
  then redirects to WHOOP; `/callback` exchanges the WHOOP code, stores the WHOOP tokens in the
  user's vault and issues the MCP grant. The grant only carries the WHOOP `user_id`, encrypted.
- `src/token-vault.ts`: the `WhoopTokenVault` Durable Object. WHOOP rotates refresh tokens on every
  use, so refreshes are serialized per user and persisted before the new access token is returned.
- `src/mcp-server.ts`: the tools. `src/webhooks.ts`: webhook verification and forwarding.
  `src/grants.ts`: listing and revoking a user's MCP grants.

One WHOOP user may have several MCP grants (one per client); they all share that user's vault.

## Disconnecting and revocation

The WHOOP token is revoked at WHOOP (`DELETE /v2/user/access`) and deleted from the vault when:

1. **The MCP client revokes its grant** (RFC 7009 on `/token`, the advertised `revocation_endpoint`,
   with the refresh token) **and it was the user's last grant**. If another MCP client is still
   connected for the same WHOOP user, WHOOP stays connected. Revoking only an access token ends that
   token, not the connection. A made-up token in the provider's format disconnects nobody: the hook
   only acts when a grant that existed before the request is gone after it.
2. **The user asks to disconnect**, through the `disconnect_whoop` tool (`{ "confirm": true }`) or
   `POST /mcp/disconnect` with the user's MCP bearer token. Both revoke WHOOP access, delete the
   vault and revoke **all** of the user's MCP grants (without WHOOP access none of them would work).
   The response is `{ "disconnected": true, "whoop_access_revoked": <bool>, "mcp_grants_revoked": <n> }`.
3. **All of the user's grants disappear without a revoke call** (grants expire after 30 days
   without use). The vault sets a Durable Object alarm; when it finds no live grant for the user it
   disconnects as above, otherwise it re-arms itself after the longest-lived grant.

Local deletion always happens, even if WHOOP's revoke call fails (users can also revoke the app from
their WHOOP account). The reverse direction is handled too: if WHOOP rejects the refresh token (the
user revoked access at WHOOP), the next MCP token refresh answers `invalid_grant` and the grant is
deleted, so the client re-authorizes instead of retrying forever.

## Webhooks

### Register the URL at WHOOP

1. In the WHOOP developer dashboard ([developer.whoop.com](https://developer.whoop.com)), open your app.
2. Under **Webhooks**, add `https://<your-worker-host>/webhooks/whoop` and choose **v2** in the
   *Model Version* dropdown. Save.
3. WHOOP signs each delivery with your app's client secret, which this Worker already has
   (`WHOOP_CLIENT_SECRET`). There is nothing else to configure for verification.

WHOOP sends `recovery.updated`, `recovery.deleted`, `sleep.updated`, `sleep.deleted`,
`workout.updated` and `workout.deleted` for users who authorized your app. In v2 the `id` is a UUID;
for recovery events it is the id of the associated sleep.

### What the Worker does

1. Verifies `X-WHOOP-Signature` = `base64(HMAC-SHA256(X-WHOOP-Signature-Timestamp + raw_body, WHOOP_CLIENT_SECRET))`
   with a constant-time check, and rejects timestamps (milliseconds) more than 5 minutes away.
   Invalid or stale signatures get `401`, malformed events `400`.
2. Answers `204` immediately. Forwarding runs in `ctx.waitUntil`, so a slow destination never makes
   WHOOP retry.
3. De-duplicates by `trace_id` (KV key with a 1 h TTL, best effort), so WHOOP retries of the same
   event are forwarded once.
4. POSTs the event to every URL in `FORWARD_WEBHOOK_URLS` (comma-separated, `https` only, up to 10),
   with up to 3 attempts per destination (retrying 5xx, 408, 429 and network errors).

With no `FORWARD_WEBHOOK_URLS` it only verifies and answers `204`. With URLs but no
`FORWARD_WEBHOOK_SECRET` (32+ characters) it refuses to forward unsigned and logs an error.

### Forwarded request format

```http
POST <your url>
Content-Type: application/json
X-Whoop-MCP-Signature-Timestamp: 1790000000000
X-Whoop-MCP-Signature: <base64 HMAC-SHA256(timestamp + raw_body, FORWARD_WEBHOOK_SECRET)>
X-Whoop-MCP-Event: recovery.updated
X-Whoop-MCP-Trace-Id: d3709ee7-104e-4f70-a928-2932964b017b
```

```json
{
  "version": 1,
  "source": "whoop",
  "user_id": 10129,
  "type": "recovery.updated",
  "id": "ecfc6a15-4661-442f-a9a4-f160dd7afae8",
  "trace_id": "d3709ee7-104e-4f70-a928-2932964b017b",
  "received_at": "2026-09-28T07:12:03.120Z",
  "recovery": { "cycle_id": 93845, "sleep_id": "ecfc6a15-4661-442f-a9a4-f160dd7afae8", "score": { "recovery_score": 67 } }
}
```

`user_id` is the WHOOP user id (the same value `get_profile` returns). `recovery` is present only
for `recovery.updated` and only when the Worker holds a token for that user (it resolves
sleep → `cycle_id` → `GET /v2/cycle/{cycleId}/recovery`); otherwise you get the bare event and can
fetch the data yourself. `*.deleted` events never carry data.

Verifying on the receiving side (any runtime with Web Crypto):

```ts
async function verifyWhoopMcpWebhook(request: Request, secret: string): Promise<unknown | null> {
  const timestamp = request.headers.get("X-Whoop-MCP-Signature-Timestamp") ?? "";
  const signature = request.headers.get("X-Whoop-MCP-Signature") ?? "";
  const raw = await request.text(); // verify the raw body, before parsing
  if (!/^\d+$/.test(timestamp) || Math.abs(Date.now() - Number(timestamp)) > 5 * 60 * 1000) return null;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  let sig: Uint8Array;
  try {
    sig = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
  const ok = await crypto.subtle.verify("HMAC", key, sig, enc.encode(timestamp + raw)); // constant time
  return ok ? JSON.parse(raw) : null; // then de-duplicate on trace_id
}
```

Answer `2xx` quickly. `5xx`, `408`, `429` and network errors are retried (3 attempts in total over a few seconds); other `4xx` answers are not.

## Deploy your own in 5 steps

You need a Cloudflare account and a WHOOP developer app ([developer.whoop.com](https://developer.whoop.com)).

1. **Clone and install**

   ```sh
   git clone https://github.com/vicens-aniol/whoop-mcp.git && cd whoop-mcp
   npm install && npx wrangler login
   ```

2. **Set your URL.** In `wrangler.jsonc`, change `PUBLIC_BASE_URL` to the URL your Worker will have
   (e.g. `https://whoop-mcp.<your-subdomain>.workers.dev`, or a custom domain). OAuth tokens are
   bound to `${PUBLIC_BASE_URL}/mcp`.

3. **Configure the WHOOP app**: redirect URI `${PUBLIC_BASE_URL}/callback`, scopes
   `offline read:profile read:body_measurement read:recovery read:cycles read:sleep read:workout`,
   and optionally the webhook URL `${PUBLIC_BASE_URL}/webhooks/whoop` (model v2).

4. **Deploy.** The KV namespace is created automatically on the first deploy.

   ```sh
   npx wrangler deploy
   ```

5. **Add the secrets** (values are prompted or piped, never typed on the command line):

   ```sh
   npx wrangler secret put WHOOP_CLIENT_ID
   npx wrangler secret put WHOOP_CLIENT_SECRET
   openssl rand -hex 32 | npx wrangler secret put CONSENT_SECRET
   # optional, webhook forwarding:
   openssl rand -hex 32 | npx wrangler secret put FORWARD_WEBHOOK_SECRET
   npx wrangler secret put FORWARD_WEBHOOK_URLS   # e.g. https://example.com/hooks/whoop
   ```

Check `GET ${PUBLIC_BASE_URL}/` (`"whoop_configured": true`), then add `${PUBLIC_BASE_URL}/mcp` as a
remote MCP server in your client. Hand `FORWARD_WEBHOOK_SECRET` to the receiver through a secret
manager, never in plain text.

### Keeping your real ids out of git

`wrangler.jsonc` is a template without account or namespace ids. To pin your own values without
committing them, copy it to `wrangler.local.jsonc` (gitignored), add `account_id`, the KV `id` and
your `PUBLIC_BASE_URL`, and deploy with:

```sh
npm run deploy:local      # wrangler deploy -c wrangler.local.jsonc
npx wrangler secret put NAME -c wrangler.local.jsonc
```

If you move to another URL later, update `PUBLIC_BASE_URL` and the WHOOP redirect URI, and reconnect
clients (existing tokens are bound to the old resource).

## Security

- WHOOP access and refresh tokens are stored only in the user's Durable Object and never exposed
  over HTTP or to MCP clients. MCP grants carry only the WHOOP user id, encrypted by the provider.
  MCP tokens, codes and client secrets are stored in KV only as hashes.
- Consent is asked per client before redirecting to WHOOP. The consent page cannot be framed, and its
  handle and the upstream `state` are single use and bound to the browser with `__Host-` cookies.
  All client-supplied metadata is HTML-escaped.
- WHOOP token refreshes are serialized per user, because WHOOP refresh tokens are single use.
- Webhooks: constant-time HMAC verification, 5 minute replay window, 64 KB body limit, forwarding
  only to `https` URLs without credentials, and never unsigned.
- All secrets are Worker secrets. `.dev.vars`, `.env*` and `wrangler.local.jsonc` are gitignored;
  `.dev.vars.example` lists the variable names with no values.
- Found a vulnerability? Please report it privately through a GitHub security advisory rather than a
  public issue.

## Development

```sh
cp .dev.vars.example .dev.vars   # fill in for `npm run dev`
npm test            # vitest inside workerd; WHOOP is mocked, no request leaves the machine
npm run type-check
npm run cf-typegen  # after changing wrangler.jsonc
```

## License

[MIT](LICENSE)
