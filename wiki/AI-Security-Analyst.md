# AI Security Analyst

The **AI Security Analyst** is a conversational, **read-only** SOC analyst embedded in SIEMBox. Ask it about your alerts, incidents, vulnerabilities, assets, and threat intelligence — and get help **prioritizing**. It can only *observe* your data through a fixed set of read-only tools; it can never change anything.

> Not to be confused with the **[AI builder](Parsers#ai-builder)** (which generates parsers/rules). The Analyst *answers questions about your environment*; the builder *authors content*. They can use the same or different models.

## Where to find it

- **Ask AI** button (top-right of every page) → opens a chat **drawer**.
- **AI Analyst** in the sidebar → a dedicated full-page view with your thread history.
- **Explain with AI** on an alert/vulnerability/log → a one-shot explanation, with an **"Ask the analyst"** hand-off that opens the drawer with that item as context.

Available to **admin**, **analyst**, and **operator** roles.

## How it works

Each turn, the model emits exactly one action — either a **tool call** or a **final answer** — as a small JSON object. SIEMBox executes the (read-only) tool, feeds the result back as data, and loops until the model answers or a budget is reached. This structured loop is **model-agnostic**, so it works on a local **Ollama** model in JSON mode just as well as on a cloud model.

**Safety properties:**
- **Read-only.** The analyst can only call the tools below — all of which are reads. It has no write/delete capability.
- **Grounded.** Every factual claim is backed by a tool result; the system prompt forbids inventing counts, IPs, CVEs, or hostnames.
- **Untrusted data.** Tool results (log lines, alert text, etc.) are treated as *data*, never as instructions — embedded "prompt-injection" content is ignored.
- **No code execution.** Model output is never executed; only a validated tool name + clamped arguments are.

## Read-only tools

| Tool | What it returns |
|------|-----------------|
| `get_system_overview` | High-level alert / vulnerability / asset summary |
| `get_alert_stats` | Alert counts by status and severity |
| `list_alerts` / `get_alert` | Recent alerts (filterable) / full alert detail |
| `alerts_by_country` | Alerts grouped by source country (GeoIP) |
| `get_vulnerability_stats` | Open/patched counts, unique CVEs |
| `get_asset_vulnerabilities` | Vulnerabilities for one asset |
| `list_assets` / `get_asset` / `get_asset_stats` | Asset inventory, detail, discovery summary |
| `lookup_ip` | Threat-feed hits + reputation for an IP |
| `search_logs` | Search parsed logs (time-bounded) |
| `list_edr_agents` | Endpoint list *(admin only)* |

The analyst typically gathers 2–4 results, then answers — it is tuned to stop investigating once it can respond.

## Configuration

The Analyst has its **own model configuration**, separate from the AI builder, under **Settings → AI Analyst** (admin):

- **Provider** — `ollama` (local), `openai`, or `anthropic`.
- **Model** — e.g. an Ollama model name, or a cloud model.
- **Base URL** — for Ollama / OpenAI-compatible endpoints.
- **API key** — for cloud providers; **encrypted at rest** with `CREDENTIAL_ENCRYPTION_KEY`.

Leave a field blank to **inherit** the main AI builder config, so you can run the Analyst on the same provider with no extra setup, or point it at a different (e.g. cheaper, local) model. See [Configuration](Configuration#ai-analyst-optional).

> Running a **local model** (Ollama) keeps your security data on your own infrastructure and avoids per-token cost — a good fit for a chatty analyst. Larger/cloud models tend to follow the tool protocol more reliably.

## Conversations

Chats are saved as **per-user threads** (you only see your own). Rename or delete threads from the thread list. Assistant replies render as sanitized Markdown, and each turn shows a collapsible **trace** of which read-only tools ran (with timing) so you can see exactly how an answer was reached.

## Example questions

- "Summarize the most critical alerts from the last 24 hours and tell me what to look at first."
- "Which assets have the most high/critical open vulnerabilities right now?"
- "Look up 203.0.113.7 — is it on any threat feeds, and what did it do in our logs?"
- "Given current alerts and vulnerabilities, what are my top three priorities?"

## Troubleshooting

- **"Not configured" banner** → set a provider/model under *Settings → AI Analyst* (or configure the AI builder, which it can inherit).
- **Errors mentioning the model/host** → usually the Ollama/cloud endpoint (model too large, server down). The Analyst is only as available as the model you point it at.
- **"Ran out of analysis steps"** is avoided in v3 — the Analyst always composes a final answer from whatever it gathered.

See also: [Configuration](Configuration) · [Threat Intel](Threat-Intel) · [SIEMBOX Endpoint](SIEMBOX-Endpoint).
