# Publishing the GitHub Wiki

The repo's [`wiki/`](../wiki) folder holds a ready-to-publish set of GitHub Wiki pages
(`Home`, `Installation`, `Configuration`, `Architecture`, `Log-Shippers`, `Parsers`,
`Detection-Rules`, `Threat-Intel`, `Vulnerability-and-Container-Scanning`,
`API-Reference`, `FAQ`, `Troubleshooting`, plus `_Sidebar`).

GitHub wikis are a **separate git repository** (`<repo>.wiki.git`), so they can't be
edited from a normal CI/sandboxed environment that's scoped to the main repo — publish
them from a machine with normal GitHub access.

## One-time setup

1. On GitHub: **repo → Settings → Features →** enable **Wikis** (if not already).
2. **Wiki tab → Create the first page** (any content) and save. This initializes the
   `*.wiki.git` repository so it can be cloned.

## Publish (and re-publish on updates)

```bash
# from the root of your SIEMBOX clone (which contains the wiki/ folder)
git clone https://github.com/cladkins/SIEMBOX.wiki.git
cp wiki/*.md SIEMBOX.wiki/
cd SIEMBOX.wiki
git add .
git commit -m "Sync wiki from repo wiki/ folder"
git push
```

That's it — `Home.md` becomes the landing page and `_Sidebar.md` renders the navigation
sidebar. Re-run the `cp … && git commit && git push` whenever the staged pages change.

## Keeping it in sync

The pages are deliberately kept in the repo (under `wiki/`) so they're version-controlled
and reviewable alongside code. Treat `wiki/` as the source of truth and re-publish after
merges that change features.
