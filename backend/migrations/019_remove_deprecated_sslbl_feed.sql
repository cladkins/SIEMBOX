-- Migration 019: remove the deprecated abuse.ch SSLBL botnet-C2 IP feed.
--
-- abuse.ch deprecated the SSLBL "Botnet C2 IP Blacklist" on 2025-01-03. The URL
-- (https://sslbl.abuse.ch/blacklist/sslipblacklist.txt) still returns HTTP 200
-- but its body is header-only — zero IPs — so the feed perpetually showed
-- "ok / 0 indicators" in the UI, which is misleading. Feodo Tracker already
-- covers the botnet-C2 category.
--
-- Migration 015 no longer seeds this feed, so once this DELETE runs the row stays
-- gone (015's idempotent re-run won't re-add it). Idempotent: deleting an absent
-- row is a no-op, and the FK cascade clears any indicators it had stored.

DELETE FROM threat_feeds WHERE slug = 'sslbl-botnet';
