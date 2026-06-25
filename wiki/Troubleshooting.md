# Troubleshooting

Start by checking container health: `docker compose -f compose.prod.yaml ps` and `docker compose -f compose.prod.yaml logs -f backend`.

## The web UI won't load

- Confirm the **frontend** and **backend** containers are `Up`.
- The UI is on **8420**; make sure that port is published and reachable (firewall/security group).
- Check `docker compose logs frontend` and `... backend` for startup errors (a missing required secret like `JWT_SECRET` or `CREDENTIAL_ENCRYPTION_KEY` will stop the backend).

## No logs are arriving

- **Syslog sources:** confirm devices target the SIEMBox host on **`514`** (UDP or TCP) and nothing is dropping it in between.
- **Shipper sources:** the shipper must be **online** in the UI. Check that `SIEMBOX_API_URL` points at **`http://<host>:8421/api`** (the **backend** port) and that the **API key** is correct.
- Raw logs show up under **Logs → Raw Logs** even before a parser matches. If you see raw but not parsed logs, you need a **parser** for that source.

## A parser isn't matching

- Use the parser **Test** tool to run a sample through the real engine.
- Regex parsers need **named groups** `(?<name>...)`; check the `pattern` actually matches your line.
- Remember `message` defaults to the **raw line** unless you map a group to it — if a `message` self-test "expects" a cleaned value, map `msg`→`message` (see [Parsers](Parsers#message-vs-the-raw-line)).
- Parser **priority** matters: the first enabled parser (lowest priority number) that matches wins; a broad parser may shadow a specific one.

## The AI builder fails or times out

- Confirm a provider/key is set in *Settings → AI Builder* (or via env).
- For **Ollama**, the base URL must be reachable **from the backend container** — bind Ollama to `0.0.0.0` and use the host LAN IP or `http://host.docker.internal:11434`, not `localhost`.
- If a generated artifact isn't fully valid, you can **Save anyway** and refine it manually.

## Threat feeds show `error`

- The free blocklists need outbound **HTTPS**. If your environment blocks egress, feeds will report `last_status=error` and simply contribute no indicators — this is non-fatal.

## Scans fail or find nothing

- **Nuclei/Trivy** need their template/cache volumes; give the first run time to warm up.
- **Docker-host image discovery** only works when the Docker socket is mounted into the backend (opt-in; see [Vulnerability & Container Scanning](Vulnerability-and-Container-Scanning#docker-host-discovery)).

## Still stuck?

See the full in-repo guides:
[Troubleshooting](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/TROUBLESHOOTING.md) ·
[Shipper Diagnostics](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/SHIPPER-DIAGNOSTICS.md), or open an [issue](https://github.com/cladkins/SIEMBOX/issues).
