# Troubleshooting

Start by checking container health: `docker compose -f compose.prod.yaml ps` and `docker compose -f compose.prod.yaml logs -f backend`.

## The web UI won't load

- Confirm the **frontend** and **backend** containers are `Up`.
- The UI is on **8420**; make sure that port is published and reachable (firewall/security group).
- Check `docker compose logs frontend` and `... backend` for startup errors (a missing required secret like `JWT_SECRET` or `CREDENTIAL_ENCRYPTION_KEY` will stop the backend).
- "Blocked by CORS policy" in the browser console: a page on another origin is calling the API, which answers browsers on its own origin only unless `CORS_ORIGIN` lists that origin. The bundled UI needs no CORS (keep `VITE_API_URL=/api`). See [TROUBLESHOOTING.md, "CORS error in the browser console"](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/TROUBLESHOOTING.md#issue-cors-error-in-the-browser-console).

## Every page sends me to "Choose a new password"

- The account signed in with a password it must replace: the initial `admin` password, SIEMBox's default `changeme`, or a temporary one an admin or `auth-admin reset-password` set. Enter the password you just signed in with and a new one, then sign in again. Scripts get `403` with `code: "PASSWORD_CHANGE_REQUIRED"` until then. See [TROUBLESHOOTING.md](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/TROUBLESHOOTING.md#issue-every-page-sends-me-to-choose-a-new-password--api-answers-403-password_change_required).

## No logs are arriving

- **Syslog sources:** confirm devices target the SIEMBox host on **`514`** (UDP or TCP) and nothing is dropping it in between.
- **Shipper sources:** the shipper must be **online** in the UI. Check that `SIEMBOX_API_URL` points at **`http://<host>:8421/api`** (the **backend** port) and that the **API key** is correct.
- Raw logs show up under **Logs → Raw Logs** even before a parser matches. If you see raw but not parsed logs, you need a **parser** for that source.
- **Gaps while the database is busy:** if Postgres can't keep up (a long query, a scan, slow disk), **UDP** syslog can only drop messages. The backend logs `Ingestion is overloaded: dropped N UDP syslog message(s)` and it appears under Recent Errors on the Admin dashboard. TCP syslog and HTTP push are slowed down instead of dropping, so send anything important over TCP. Details and tuning: [Logs are dropped or ingestion is slow](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/TROUBLESHOOTING.md#issue-logs-are-dropped-or-ingestion-is-slow).

## A parser isn't matching

- Use the parser **Test** tool to run a sample through the real engine.
- Regex parsers need **named groups** `(?<name>...)`; check the `pattern` actually matches your line.
- Remember `message` defaults to the **raw line** unless you map a group to it — if a `message` self-test "expects" a cleaned value, map `msg`→`message` (see [Parsers](Parsers#message-vs-the-raw-line)).
- Parser **priority** matters: the first enabled parser (lowest priority number) that matches wins; a broad parser may shadow a specific one.

## The AI builder fails or times out

- Confirm a provider/key is set in *Settings → AI Builder* (or via env).
- For **Ollama**, the base URL must be reachable **from the backend container** — bind Ollama to `0.0.0.0` and use the host LAN IP or `http://host.docker.internal:11434`, not `localhost`.
- If a generated artifact isn't fully valid, you can **Save anyway** and refine it manually.

## An AI answer is cut off

- An answer that hit a limit says so at the end (*This answer hit the N-token output limit...*, *I used all N data lookups...*, *I reached the N-second time budget...*) and names the setting. An admin raises it under **Settings → AI → AI budgets** — see [AI budgets](AI-Security-Analyst#answer-length-lookups-and-time-ai-budgets). Longer limits are slower and, with a paid provider, cost more.
- Generation that fails with *The AI response hit the N-token output limit* needs a higher **Builder output length** there (or fewer sample lines).
- If raising a length changes nothing, the model's own output limit is lower: use a model with a larger one (for Ollama, also check `num_ctx`).
- A *Request timed out* while the Analyst works behind your own reverse proxy: allow a read timeout above the Analyst's time budget + 120 s (the bundled frontend allows 420 s).

## Threat feeds show `error`

- The free blocklists need outbound **HTTPS**. If your environment blocks egress, feeds will report `last_status=error` and simply contribute no indicators — this is non-fatal.

## Scans fail or find nothing

- **Nuclei/Trivy** need their template/cache volumes; give the first run time to warm up.
- **Docker-host image discovery** only works when the Docker socket is mounted into the backend (opt-in; see [Vulnerability & Container Scanning](Vulnerability-and-Container-Scanning#docker-host-discovery)).

## Still stuck?

See the full in-repo guides:
[Troubleshooting](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/TROUBLESHOOTING.md) ·
[Shipper Diagnostics](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/SHIPPER-DIAGNOSTICS.md), or open an [issue](https://github.com/cladkins/SIEMBOX/issues).
