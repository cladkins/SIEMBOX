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
- **Read-only.** The analyst's built-in tools below are all reads. It has no write/delete capability in SIEMBox. The one way to give it more is an admin connecting an [MCP server](#mcp-servers-optional) and switching a tool on.
- **Grounded.** Every factual claim is backed by a tool result; the system prompt forbids inventing counts, IPs, CVEs, or hostnames.
- **Untrusted data.** Tool results (log lines, alert text, etc.) are treated as *data*, never as instructions — embedded "prompt-injection" content is ignored.
- **No code execution.** Model output is never executed; only a validated tool name + clamped arguments are.

## Read-only tools

| Tool | What it returns |
|------|-----------------|
| `get_system_overview` | High-level alert / vulnerability / asset summary |
| `get_alert_stats` | Alert counts by status and severity |
| `list_alerts` / `get_alert` | Recent alerts (filterable) / full alert detail, by id or reference (`ALR-4821`) |
| `alerts_by_country` | Alerts grouped by source country (GeoIP) |
| `get_vulnerability_stats` | Open/patched counts, unique CVEs |
| `get_asset_vulnerabilities` | Vulnerabilities for one asset |
| `list_assets` / `get_asset` / `get_asset_stats` | Asset inventory, detail, discovery summary |
| `lookup_ip` | Threat-feed hits + reputation for an IP |
| `search_logs` | Search parsed logs (time-bounded) |
| `list_edr_agents` | Endpoint list *(admin only)* |
| `get_asset_context` | Asset-360 for one host: EDR agent, log shipper, GeoIP, open vulns, recent alerts |
| `get_related_alerts` | Other recent alerts sharing the same rule, asset, or source IP as a given alert |
| `get_alert_history_stats` | How a rule/title has historically been dispositioned (new/investigating/closed/false_positive counts) |

The alert tools take an alert id or its [reference](Detection-Rules#alert-references-alr-) and return each alert's `ref`.

## MCP servers (optional)

An admin can connect remote [MCP](https://modelcontextprotocol.io) (Model Context Protocol) servers under **Settings → AI → MCP servers**. Their tools join the analyst's menu next to the built-in ones, named `mcp__<server>__<tool>`: a ticket system, a threat intelligence service, your firewall's API, your own tooling.

**Adding a server.** Give it a short name (lowercase letters, digits, underscores), its URL, and, when it needs authentication, a header name and value (for example `Authorization` and `Bearer <token>`). SIEMBox connects from the backend over the **Streamable HTTP** transport, so the backend container must reach the URL. Servers that only run as a local command (stdio) are not supported directly; put them behind an HTTP gateway.

**You choose every tool.** On the first sync, tools the server marks read-only start switched on. All others start off. The card lists each tool with its kind (*read-only* or *may change data*) and a switch. Only switched-on tools are offered to the model. The read-only mark is the server's own claim, so review the list for a server you do not run yourself.

**What changes about safety:**
- A built-in tool only reads SIEMBox data. An MCP tool does whatever its server does. When a tool marked *may change data* is on, the analyst is told to call it only when you ask for that action in your own message, never because a log line, alert or tool result suggests it. A model can still be misled, so switch on write-capable tools with care.
- Tool arguments the model writes go to the MCP server, and tool results go to your AI provider like any other tool result.
- The analyst sees the tool descriptions stored at the last sync, not a live copy. **Sync tools** fetches the list again. A tool whose description or arguments changed is switched off until you review it.
- The header value is encrypted at rest (it needs `CREDENTIAL_ENCRYPTION_KEY`), is never shown again, and is only sent to the URL it was saved for: changing the URL asks for it again and clears the tool list. Redirects are refused.
- Limits: 10 servers, 100 tools per server, 40 MCP tools offered per question, 20 s per request to a server. Results count against the same per-question data limits as built-in tools.

**AI Triage.** Each server has a separate **Use in AI Triage** switch, off by default. Triage runs unattended on alert content an attacker can influence. With the switch on, triage gets the tools that are **On** and whose own **Triage** switch is on. The Triage switch starts on for tools the server marks read-only and off for the rest. Each lookup sends alert details to that server.

You can override the Triage switch per tool, in either direction. Many servers do not mark their lookup tools read-only: switch Triage on for such a tool to let triage use it (the page asks you to confirm). Or switch it off to keep a read-only tool out of triage. Allow a tool that is not marked read-only only when it is a lookup that changes nothing: no operator is present when triage calls it. Triage is told to use such tools for lookups only, but a model can be misled by alert content. If a later sync finds the tool's definition changed, the override is dropped along with the tool's On switch.

## Citing alerts

Every alert has a reference such as **`ALR-4821`**. The analyst cites alerts by reference in its answers, and AI Triage does the same in its reasoning, so you can quote an answer and still know exactly which alert it meant. Ask about one directly — "What happened in ALR-4821?" or "Is ALR-4821 related to anything else?" — and the analyst looks it up. In the chat and in a triage verdict, each `ALR-####` is a link that opens the alert on the Alerts page (the link is built from the number alone, so model output can't point it anywhere else).

The analyst typically gathers 2–4 results, then answers — it is tuned to stop investigating once it can respond. How many lookups it may make, how long it may take and how long its answer may be are set under [AI budgets](#answer-length-lookups-and-time-ai-budgets).

## Configuration

The Analyst has its **own model configuration**, separate from the AI builder, under **Settings → AI Analyst** (admin):

- **Provider** — `ollama` (local), `openai`, or `anthropic`.
- **Model** — e.g. an Ollama model name, or a cloud model.
- **Base URL** — for Ollama / OpenAI-compatible endpoints.
- **API key** — for cloud providers; **encrypted at rest** with `CREDENTIAL_ENCRYPTION_KEY`.

Leave a field blank to **inherit** the main AI builder config, so you can run the Analyst on the same provider with no extra setup, or point it at a different (e.g. cheaper, local) model. See [Configuration](Configuration#ai-analyst-optional).

> Running a **local model** (Ollama) keeps your security data on your own infrastructure and avoids per-token cost — a good fit for a chatty analyst. Larger/cloud models tend to follow the tool protocol more reliably.

## Answer length, lookups and time (AI budgets)

**Settings → AI → AI budgets** (admin) sets how much the Analyst may write and how long it may work:

| Setting | What it limits | Default |
|---|---|---|
| **Answer length** | Tokens in the written answer | 4000 |
| **Working-step length** | Tokens in each step that picks a lookup (a short answer can come back in one) | 1500 |
| **Max data lookups** | Read-only tool calls per question | 10 |
| **Time budget** | Seconds of gathering before it must answer with what it has | 180 |

The same card has AI Triage's verdict length, working-step length, lookups and time budget, the AI builders' output length (parser/rule generation, default 8000) and the **Explain with AI** answer length (default 3000).

Higher limits give more complete answers, but they are slower, and with a paid provider every output token costs money. The model's own output limit still applies. A token is roughly ¾ of a word.

**When a limit is reached, the answer says so.** An answer cut off at its length limit ends with *This answer hit the 4000-token output limit, so it may be cut off. An admin can raise "Answer length" in Settings → AI → AI budgets.* An answer written after the Analyst used all its lookups, or ran out of time, says which and names the setting. A working step that was cut off is not retried: the Analyst answers from what it had gathered. Triage verdicts carry the same notes at the end of their reasoning.

The Analyst answers inside one web request: up to the time budget for gathering, plus up to 2 minutes to write the answer. If you run SIEMBox behind your own reverse proxy, give it a read timeout above that (the bundled frontend allows 420 s), or the browser shows a timeout while the answer is still being written. See [Troubleshooting: AI answer is cut off](Troubleshooting).

## Conversations

Chats are saved as **per-user threads** (you only see your own). Rename or delete threads from the thread list. Assistant replies render as sanitized Markdown, and each turn shows a collapsible **trace** of which read-only tools ran (with timing) so you can see exactly how an answer was reached.

## Automated triage

Beyond the interactive chat, SIEMBox can run the **same read-only tool loop automatically** on new alerts to produce a structured, saved verdict instead of a conversational answer — a first-pass triage so an operator doesn't have to manually chase every alert's context by hand.

**Off by default, and gated when on:**
- **Opt-in** — nothing runs until an admin enables it under *Settings → AI Triage*.
- **Severity-gated** — only alerts at or above a configurable minimum severity (default: medium) are analyzed.
- **Cost-bounded** — a daily cap on analysis runs, a per-process concurrency limit, and a dedupe window that skips re-analyzing an equivalent alert (same rule + title) triaged recently.

**What it produces**, per alert:
- A **verdict** (`true_positive` / `false_positive` / `suspicious` / `inconclusive`) and a **0-100 risk score**, with a confidence level.
- A short **summary** and markdown **reasoning**, grounded in evidence it gathered via the tools above.
- **Suggested next-step queries** — specific follow-ups an operator (or the interactive analyst) could run.
- A **proposed remediation plan** (status suggestion, urgency, imperative steps) — this is always *data for a human to act on*, never an executed action. Applying it (e.g. changing the alert's status) still goes through the normal manual `Update Status` flow; triage has no write path of its own.

**Same safety model as the chat analyst**, with one addition: because there's no human typing the question, the alert record itself (title, description, matched data — all attacker-influenced content) is explicitly treated as untrusted data in the prompt, on top of the existing untrusted-tool-result handling. The output is also schema-validated: an unrecognized verdict, an out-of-range risk score, or a suggested query naming a tool that doesn't exist is corrected or dropped in code before it's ever stored, so a model behaving badly can skew a verdict but can't do anything else.

**Where to see it:**
- A **Triage** column and a per-alert tab in Alerts' detail view.
- A dedicated **SOC Triage** page (sidebar, under SIEM) — a queue view across all triaged alerts, sortable by risk score and filterable by verdict/status, for scanning many at once.

Configuration is a **third independent model selection** (provider/model/base URL/key), inheriting the AI Analyst (chat) config when left unset — see [Configuration](Configuration#ai-triage-optional).

## Example questions

- "Summarize the most critical alerts from the last 24 hours and tell me what to look at first."
- "Which assets have the most high/critical open vulnerabilities right now?"
- "Look up 203.0.113.7 — is it on any threat feeds, and what did it do in our logs?"
- "Given current alerts and vulnerabilities, what are my top three priorities?"
- "Explain ALR-4821 and list anything related to it."

## Troubleshooting

- **"Not configured" banner** → set a provider/model under *Settings → AI Analyst* (or configure the AI builder, which it can inherit).
- **Errors mentioning the model/host** → usually the Ollama/cloud endpoint (model too large, server down). The Analyst is only as available as the model you point it at.
- **"Ran out of analysis steps"** is avoided in v3 — the Analyst always composes a final answer from whatever it gathered.

See also: [Configuration](Configuration) · [Threat Intel](Threat-Intel) · [SIEMBOX Endpoint](SIEMBOX-Endpoint).
