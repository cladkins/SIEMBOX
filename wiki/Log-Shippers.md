# Log Shippers

The **log shipper** is a small, standalone container you install on any host whose logs you want in SIEMBox — a web server, a NAS, a Docker host, etc. It authenticates to the main stack with an **API key** and forwards logs over the network. It does **not** need the rest of the SIEMBox stack running locally.

> Prefer syslog? Devices that already emit syslog can send directly to `udp/tcp 514` on the SIEMBox host with no shipper. The shipper is for hosts where you want to collect *files*, *Docker container logs*, or the *systemd journal*.

## What it can collect

- **Log files** — any path you mount (e.g. `/var/log/...`).
- **Docker container logs** — by mounting the Docker socket on that host.
- **systemd journal** — by mounting the journal directory.

## Setup

1. **In the SIEMBox UI:** *Log Shippers → Add Shipper* → copy the generated **API key**.
2. **On the host you want to collect from:**

   ```bash
   mkdir siembox-shipper && cd siembox-shipper
   curl -O https://raw.githubusercontent.com/cladkins/SIEMBOX/main/log-shipper/compose.prod.yaml

   cat > .env << 'EOF'
   SHIPPER_API_KEY=paste-your-api-key-here
   SIEMBOX_API_URL=http://your-siembox-ip:8421/api
   EOF
   ```

   Note the **backend port `8421`** in the URL.

3. **Edit `compose.prod.yaml`** and uncomment the volume mounts for the logs you want to ship (Docker socket, `/var/log` paths, journal, …).
4. **Start it:**

   ```bash
   docker compose -f compose.prod.yaml up -d
   ```

The shipper should show as **online** in the UI within ~30 seconds.

Two compose files are provided in [`log-shipper/`](https://github.com/cladkins/SIEMBOX/tree/main/log-shipper):

| File | Use it for |
|------|-----------|
| `log-shipper/compose.prod.yaml` | **Recommended — standalone.** Pre-built image; needs only this file + `.env`. |
| `log-shipper/compose.yaml` | Builds the shipper image locally from source. |

## Verifying & troubleshooting

- The **Log Shippers** view shows each shipper's online status and recent activity.
- If a shipper is offline or logs aren't arriving, see [Troubleshooting](Troubleshooting) and the in-repo guides:
  [Log Shipper README](https://github.com/cladkins/SIEMBOX/blob/main/log-shipper/README.md) ·
  [Verification Guide](https://github.com/cladkins/SIEMBOX/blob/main/log-shipper/VERIFICATION-GUIDE.md) ·
  [Shipper Diagnostics](https://github.com/cladkins/SIEMBOX/blob/main/docs/operations/SHIPPER-DIAGNOSTICS.md)

## After logs arrive

Logs land as **raw logs** immediately. To turn them into structured, searchable events, install a **[Parser](Parsers)** for that source (or generate one with AI), then add **[Detection Rules](Detection-Rules)**.
