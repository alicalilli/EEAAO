# How the bots fit into the app (v1, passive only)

## The short version

The app is still the same local dashboard (`127.0.0.1` only) with the same scope
guard. v1 adds a **bot workforce** inside it, organised in **departments**. You
open a program, go to the **Bots** tab, and press **Run** on a department. Its bots
run one after another in the background; you watch their progress live, and
their output lands in four new tabs:

| Tab | What is in it |
|---|---|
| **Findings** | Deduplicated cards with evidence: things that may be reportable. Always unverified until you confirm them. |
| **Leads** | Things worth *your* manual attention. Nothing there was tested. |
| **Inventory** | Everything collected: hosts, DNS records, live sites, URLs, parameters, forms, JS files, public files, external links, buckets, GitHub hits. |
| **Request log** | Every single request any bot made: to targets, to data sources, and DNS. |

## The pipeline

```
 Scope guard (default deny, out-of-scope wins, automation switch)
        │
 ┌──────┴────────────────────────────────────────────────┐
 │  Recon            builds the inventory                 │
 │  subdomains → dns → live hosts → public files →        │
 │  crawler → archive → github → buckets                  │
 └──────┬────────────────────────────────────────────────┘
        │ inventory + stored responses (database)
 ┌──────┴──────┬──────────┬──────┬───────────┬──────────┬────────────┬───────┐
 Headers     Cookies     TLS   Content/JS   DNS &      Third-party   Leads
                                            takeover   links
```

Recon is the only department that *finds* things to look at. It also **stores
every response it fetches** (capped at 3 MB each). Most later departments
(Headers, Cookies, Content/JS, Leads) therefore just *read what Recon already
downloaded* and send few or no new requests to the target. TLS does one
ordinary handshake per host; DNS & takeover works from the stored DNS records;
Third-party looks at the external links the crawler noted.

## Rules every bot follows (enforced in code, not by convention)

A bot cannot build its own network client. It gets three doors from
`BotContext`, all in `eeaao/bots/net.py`:

1. **TargetClient** (for the program's own hosts)
   - checks **every URL and every redirect hop** with the scope guard; an
     out-of-scope redirect is recorded but never followed
   - **GET and HEAD only**: there is no way to send a body, so nothing is ever submitted
   - one **rate limiter per program**, shared by all bots and runs
   - sends the program's **required headers** and an honest User-Agent
   - refuses hostnames that resolve to private/loopback addresses (so a scope
     entry can never reach your own machine or LAN)
   - caps response size, logs every request
2. **SourceClient** (for passive data sources: crt.sh, CertSpotter, AlienVault OTX,
   Wayback Machine, GitHub API, OSV.dev, IANA, GitLab API, and domain registries'
   RDAP servers taken from IANA's list)
   - refuses any host that is not on that fixed list, so it cannot be used against a target
   - never sends your program headers (your identity stays out of third-party logs)
   - polite per-source rate limits, logged
3. **DnsClient**: lookups only for in-scope names, rate-limited, logged

Runs are refused outright when the program's **"allows automated scanning"**
switch is off, or when the scope has unreadable entries.

What v1 bots never do: inject payloads, fuzz, guess paths, brute force, submit
forms, use a found credential, request a URL that was only seen in an archive,
or contact a bucket. robots.txt, sitemap.xml and security.txt are published
standard locations, not guesses. The crawler follows robots.txt by default and
skips logout/delete-style links.

## Findings, leads, dedup, exclusions

- Each result type has an id (for example `github_secret`, `missing_hsts`); the full
  list for all 8 departments lives in `eeaao/bots/catalog.py`.
- A card is identified by its type plus a key (such as the URL and the masked
  secret). Seeing it again only bumps "seen N×" and "last seen".
- **Program exclusions**: in Edit program → "Out-of-scope bug types", tick the
  types the program does not accept. Those cards are still recorded but marked
  **Excluded** and hidden unless you tick "Show excluded".
- Secrets are stored and shown **masked**.

## Recon department (built)

| Bot | Talks to | Produces |
|---|---|---|
| Subdomain | crt.sh, CertSpotter, OTX passive DNS (for `*.domain` scope entries) | hosts (out-of-scope names dropped) |
| DNS | your system resolver | A + CNAME for every host; MX/TXT/NS for scope roots; flags names that don't resolve |
| Live host | target (`/` or the scoped path, HTTPS and HTTP) | live sites: status, title, redirects, server, tech fingerprint |
| Public files | target: robots.txt, sitemap.xml (+ nested), security.txt | public files; URLs from sitemaps and robots |
| Crawler | target, GET only | pages, URLs, parameters, forms (never submitted), JS files (downloaded), external links |
| Archive | Wayback CDX API | old URLs + parameters + JS (never requested); leads for sensitive-looking archived files |
| GitHub | GitHub code search (your token) | GitHub hits; **findings** for likely secrets; leads for internal-looking hosts |
| Bucket | stored pages/JS + inventory | buckets referenced; one lead per bucket (never contacted) |

Limits (pages per host, total pages, depth, JS files, archive size, GitHub
searches) are under **Limits** on the Recon card.

## Headers department (built)

Sends **no requests**. It reads the 2xx responses Recon stored (one per final
URL, re-checked against the current scope), so run Recon first. Responses are as
fresh as the last Recon run; each card shows when the response was fetched.

| Bot | Flags | Grouped by | Severity |
|---|---|---|---|
| Security headers | missing CSP (header or `<meta>`; Report-Only doesn't count), HSTS (HTTPS only), X-Frame-Options (or CSP frame-ancestors), X-Content-Type-Options: nosniff, Referrer-Policy (header or `<meta>`), Permissions-Policy | site | info (HSTS low) |
| CSP quality | no script limit, `'unsafe-inline'` without nonce/hash, `'unsafe-eval'`, `*`/bare schemes, library/user-content CDNs in script-src; also notes missing object-src / base-uri. Respects `'strict-dynamic'`; with several policies only weaknesses *all* share count | site + policy | low if scripts are effectively unrestricted, else info |
| Version disclosure | version numbers in Server, X-Powered-By, X-AspNet(Mvc)-Version, X-Generator, Via… | site + header value | info |
| CORS | `*` + credentials (not exploitable as-is), `null` + credentials, plain-http origin + credentials. No Origin header is ever sent | site + case | info / medium / low |
| Cache | account/API/login-looking pages (session cookie, password field, sensitive path) without no-store/private/no-cache; `public` with Set-Cookie | page | info (public+cookie: low) |
| Clickjacking | pages with forms or account-looking paths that can be framed (ALLOW-FROM and `frame-ancestors *` count as unprotected) | page | low with POST/password form, else info |

Missing-header results say plainly that many programs exclude them; tick those
types under the program's exclusions to hide them.

## Cookies department (built)

Sends **no requests**. Reads every Set-Cookie in stored responses, **including
redirect responses**: since v1-cookies, Recon stores each redirect hop under its
own URL (headers only) and the final page under its final URL, because sites
often set the session cookie on a 302. Deleted cookies (empty value, Max-Age=0,
past Expires) are ignored. Cookie values are always masked.

Only **session-like** cookies are flagged (name such as `sessionid`, `auth`,
`token`, `PHPSESSID`, or a long random value), never analytics, consent or
preference cookies. Every cookie still goes into **Inventory → Cookies** with
its attributes.

| Bot | Flags | Severity |
|---|---|---|
| Cookie flags | no `Secure` when set over HTTPS (`__Secure-`/`__Host-` names exempt); no `HttpOnly` (CSRF-token cookies exempt, JS must read them); `SameSite` missing or `None` | low / low / info |
| Cookie scope | `Domain=` a parent domain, so every subdomain receives it. Evidence lists inventoried subdomains that CNAME to third parties or don't resolve: the hosts that would matter for a takeover | low |

A cookie is grouped per host + name, one card each, however many pages set it.

## TLS department (built)

Works on the HTTPS endpoints Recon found live. TLS handshakes go through a
fourth door, **TlsClient** (`net.py`), with the same rules as HTTP: scope check
on an in-scope `https://` URL, shared program rate limit, private-address
refusal, and a row in the request log for every handshake (kind `tls`). No HTTP
request is sent by Certificate or Protocol; the HTTPS bot sends nothing at all.

Handshakes per endpoint:

| Handshake | When |
|---|---|
| **verify**: what a browser does (trusted chain + hostname) | always, once, shared by both bots |
| **inspect**: no verification, just to read the certificate | only if verify failed on the certificate |
| **legacy TLS 1.0** and **legacy TLS 1.1**: offer only that version | Protocol bot, unless switched off under **Options** on the TLS card, or skipped when the normal handshake already chose an old version |

So 1 to 4 handshakes per endpoint. There is no cipher-by-cipher enumeration;
SSLv2/SSLv3 are not checked (modern OpenSSL cannot speak them).

| Bot | Flags | Severity |
|---|---|---|
| Certificate | expired / not yet valid (expiring within 14 days: info); name mismatch; self-signed; untrusted for another reason (often a missing intermediate: check in a browser); MD5/SHA-1 signature or RSA < 2048 / small EC key | low (mismatch on an IP: info; untrusted: info) |
| Protocol | TLS 1.0 / 1.1 accepted; the normal handshake picked a weak cipher (RC4, DES/3DES, NULL, export, anonymous, MD5) or one without forward secrecy (info) | low / info |
| HTTPS | `http://` answers with content instead of redirecting to HTTPS (info if the HTTPS site sends HSTS), or a host only on HTTP; HTTPS pages loading scripts/frames/styles, images, or posting forms over `http://` (canonical/alternate links are ignored) | low / info |

Each endpoint also appears under **Inventory → TLS endpoints** (protocol, cipher,
trust result, certificate subject, issuer, expiry, old versions accepted).

## Content and JavaScript department (built)

Reads stored pages and JavaScript. Only two kinds of requests:
a **GET for a source map** that a stored JavaScript file itself names (never a
guessed `.map` URL; capped, default 50, under **Options**), and a query to the
**OSV.dev** vulnerability database with a library name and version (switchable;
nothing about the program is sent).

| Bot | Flags | Severity |
|---|---|---|
| Secrets | API keys, tokens, private keys, credential assignments in JS and pages (same patterns as the GitHub bot; placeholders skipped; every secret masked, also inside context snippets). Google API keys are info (often meant to be public) | per key type: high / medium / low / info |
| Endpoints | inventories in-scope API paths and URLs found in JS (**Inventory → JS endpoints**), adds new in-scope hosts; flags internal-looking hostnames and private IPs. Hosts the program explicitly excludes are skipped entirely | info |
| Source map | referenced maps that download as real source maps; notes file names and whether original source code is included | low with source code, else info |
| Debug | framework debug pages (Django, Laravel/Whoops, Rails, ASP.NET, Symfony), Python/Java/.NET/Node stack traces, PHP and SQL errors, server file paths, in any stored response including 404/500s; HTML comments with words like TODO/password/staging | low / info |
| Outdated library | versions from script URLs (cdnjs, jsDelivr, unpkg, Google, `name-1.2.3.js`) and file banners (jQuery, jQuery UI, AngularJS, Bootstrap, Vue, Moment, Lodash, Underscore, Handlebars, DOMPurify, Knockout) checked against OSV npm advisories. **Inventory → Libraries** lists all | low if any HIGH/CRITICAL advisory, else info |

Server software versions (nginx, PHP…) stay with the Version disclosure bot:
OSV has no reliable data for them.

## DNS and takeover department (built)

| Bot | Works from | Flags | Severity |
|---|---|---|---|
| Takeover | CNAMEs and pages Recon stored (no requests) | CNAME to one of ~20 services (GitHub Pages, Heroku, S3, Azure, Shopify, Fastly, Netlify, Zendesk…) **and** the page shows that service's "unclaimed" message, or the target no longer resolves where that is a known sign (Azure, Elastic Beanstalk); any CNAME outside the program's domains that no longer resolves | medium / medium / low |
| NS | names whose DNS lookup failed with **SERVFAIL** in the last DNS run; one NS lookup each | broken delegation (possible dangling NS); evidence names known DNS providers | low |
| Email security | stored TXT records + one `_dmarc.<domain>` lookup per in-scope mail domain | SPF missing / several records / `+all` / `?all` / no `all`; DMARC missing / several records / `p=none` / `pct` below 100 | info, `+all` and duplicate records low |

The bots never claim or register anything. DKIM is **not** checked: selector
names can only be found by guessing, which v1 does not do. The `_dmarc` lookup is
allowed because it belongs to an in-scope domain (`DnsClient` checks the
domain, and only accepts `_underscore.` names under it). Mail domains are scope
entries that name a domain itself plus in-scope hosts with MX records, so
a scope of only `*.example.com` gives no mail domain.

## Leads department (built)

Sends no requests. A lead is a pointer for manual work, never a tested result.

| Bot | Flags | Severity |
|---|---|---|
| Redirect leads | parameters named like url, redirect, next, return_to, continue, dest, goto, callback_url… | low when the example value already is a URL or path, else info |
| XSS leads | parameter values the crawler sent that came back **verbatim** in the page, with the context (script block, tag attribute, text, comment, textarea/title); parameters whose names are often echoed (q, search, message, callback…); forms with free-text fields | low for observed reflection, else info |

## Code map

```
eeaao/
  app.py            API (programs, scope, runs, findings, inventory, log, settings)
  db.py             SQLite tables: programs, runs, run_events, requests,
                    assets, responses, findings, settings
  scope.py          scope guard (+ host check and seed helpers for bots)
  bots/
    catalog.py      departments, bots, result types (incl. planned ones)
    net.py          TargetClient / SourceClient / DnsClient / rate limiter
    base.py         BotContext: the only API a bot uses
    extract.py      pure parsing: HTML, tech fingerprints, secrets, buckets
    recon.py        the 8 Recon bots
    stored.py       read-only view of stored responses (for analysis departments)
    headers.py      the 6 Headers bots
    cookies.py      the 2 Cookies bots
    tls.py          the 3 TLS bots
    content.py      the 5 Content and JavaScript bots
    takeover.py     the 3 DNS and takeover bots
    leads.py        the 2 Leads bots
    thirdparty.py   the 2 Third-party links bots
    runner.py       starts/stops runs in the background
tests/
  test_scope.py     scope guard
  test_recon.py     Recon against a fake internet + safety assertions
  test_headers.py   Headers from stored responses; asserts zero network use
  test_cookies.py   Cookies + redirect-hop storage
  test_tls.py       TLS with a fake connector and generated certificates
  test_more_departments.py  Content/JS, DNS and takeover, Leads
  test_thirdparty.py RDAP and platform-API checks; asserts linked sites are never contacted
  fixtures/site/    tiny local website for manual end-to-end runs
  fixtures/serve.py serves it on 127.0.0.1: HTTP on 8799 (cookies, cookie-setting
                    redirect) and HTTPS on 8798 (self-signed, wrong name, TLS 1.0 on)
```

## Trying it safely

Start the fixture site with `.venv/Scripts/python tests/fixtures/serve.py`
(HTTP on port 8799, HTTPS on 8798), add a program with in-scope
`127.0.0.1:8799` and `127.0.0.1:8798`, turn automation on, and run Recon.

## Third-party links department (built)

The linked sites are out of scope, so this department **never visits them**.
It works from the external links the crawler recorded (only links found on
in-scope pages) and asks authorities about them instead:

- **Domain registries over RDAP** (the official, structured successor of WHOIS).
  The registry server for each top-level domain comes from IANA's bootstrap list
  (`data.iana.org`); only those servers are accepted, over HTTPS, at 1 request
  per second each. Well-known domains (google.com, github.com, CDNs…) and the
  program's own domains are skipped. Some country registries have no RDAP
  service; those domains are listed as "not checked".
- **Public platform APIs** for social handles: GitHub (`/users/<name>`, your
  token is used if set) and GitLab (users, then public groups). Other
  platforms (X, Instagram, Facebook, LinkedIn, YouTube, TikTok…) have no such
  API, so their links go to **Inventory → Social links** for a manual look.

| Bot | Flags | Severity |
|---|---|---|
| Broken link | linked domain **not registered**, **being deleted** (pending delete / redemption), or past its expiry date | by how the site uses it: script high, frame/stylesheet/form medium, plain link low; "expired but still in the registry" one step lower |
| Social handle | linked GitHub or GitLab account that does not exist (GitLab: or is a private group) | low |

Neither bot registers or claims anything. **Inventory → Linked domains** shows
each domain's registry answer.

## Coverage

All 8 departments and 31 bots are built.
