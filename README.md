# Everything Everywhere All at Once

A local, browser-based workspace for bug bounty hunting. You add the programs
you have joined, paste their scope, and a team of **31 passive bots in 8
departments** builds an inventory of the target and turns what it observes
into deduplicated finding cards and leads for your manual work.

> **Authorized use only.** Run it only against targets that are in scope of a
> bug bounty program you have joined, or systems you own or have written
> permission to test, and follow each program's rules, including scope, rate
> limits and its policy on automated tools. You are responsible for how you use
> it.

## What "passive" means here

v1 only reads public data and the normal responses a visitor would get. The bots
**never** inject payloads, fuzz, guess paths, brute force, submit forms, use a
credential they find, or try to exploit anything. Findings are unverified
observations; confirming them is your job.

The rules are enforced in code, not by convention. A bot cannot open its own
network connection; it gets four doors, all in `eeaao/bots/net.py`:

| Door | Used for | Rules |
|---|---|---|
| Target client | the program's own hosts | every URL **and every redirect hop** checked by the scope guard; GET/HEAD only; one rate limit per program shared by all bots; the program's required headers sent; hostnames resolving to private addresses refused; every request logged |
| TLS client | handshakes with in-scope HTTPS endpoints | same checks; at most 4 standard handshakes per endpoint |
| DNS client | lookups of in-scope names | scope-checked, rate-limited, logged |
| Source client | passive data sources (crt.sh, CertSpotter, OTX, Wayback Machine, GitHub, OSV.dev, IANA/RDAP registries, GitLab) | fixed allowlist, so it can never be pointed at a target; your program headers are never sent to them; logged |

Nothing runs for a program until you tick **"This program allows automated
scanning"**, and a scope list with an unreadable entry allows nothing.

## Departments

| Department | Bots | Network use |
|---|---|---|
| **Recon** | subdomains (CT logs, passive DNS), DNS records, live hosts + tech, robots/sitemap/security.txt, crawler, Wayback archive, GitHub code search, cloud bucket references | the only department that browses the target |
| **Headers** | security headers, CSP quality, version disclosure, CORS, caching, clickjacking | none: reads stored responses |
| **Cookies** | Secure / HttpOnly / SameSite, cookies shared with all subdomains | none |
| **TLS** | certificates, old TLS versions and weak ciphers, HTTP→HTTPS and mixed content | TLS handshakes only |
| **Content and JavaScript** | secrets, hidden endpoints and internal hosts, public source maps, debug output, libraries with known CVEs | fetches only source maps the JavaScript names; asks OSV.dev about library versions |
| **DNS and takeover** | subdomain takeover signs, broken NS delegation, SPF/DMARC | a few DNS lookups |
| **Third-party links** | links to unregistered or expiring domains, links to GitHub/GitLab accounts that don't exist | asks domain registries (RDAP) and public APIs; never visits the linked sites |
| **Leads** | redirect-style parameters, reflected parameter values, free-text forms | none |

Each program can mark bug types as out of scope; those results are still
recorded but labelled **Excluded** and hidden by default.
Full details per bot: [docs/BOTS.md](docs/BOTS.md).

## Install

Requires Python 3.11 or newer.

```bash
python -m venv .venv
```

Windows:

```bash
.venv/Scripts/python -m pip install -r requirements.txt
```

macOS / Linux:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## Run

```bash
.venv/Scripts/python -m uvicorn eeaao.app:app --host 127.0.0.1 --port 8765
```

(on macOS / Linux use `.venv/bin/python`), then open http://127.0.0.1:8765.

The app listens on 127.0.0.1 only and rejects requests addressed to any other
host name. Everything it learns is stored in `data/eeaao.db` on your machine,
which is excluded from git.

**Optional:** the GitHub bot needs a GitHub token for code search. Add it under
**Settings** (stored locally, never shown again) or set `GITHUB_TOKEN`. A
fine-grained token with no repository access is enough.

## Try it without touching anything real

A small local test site with deliberate problems (missing headers, weak cookies,
a self-signed TLS certificate that still accepts TLS 1.0, a public source map,
reflected parameters...) is included:

```bash
.venv/Scripts/python tests/fixtures/serve.py
```

It serves `http://127.0.0.1:8799` and `https://127.0.0.1:8798`. Add a program
with those two entries in scope, turn automation on, run **Recon**, then the
other departments.

## Tests

```bash
.venv/Scripts/python -m unittest
```

The tests run every department against a simulated internet and check the
safety rules as well as the results: no out-of-scope request, no request
method other than GET/HEAD, required headers sent only to targets, analysis
departments sending zero requests, secrets always masked.

## Status

v1 (passive). Active testing is deliberately out of scope for this version.
Design polish is planned.

## License

[MIT](LICENSE)
