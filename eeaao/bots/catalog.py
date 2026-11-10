"""The org chart: every department, every bot, and every kind of result a bot
can report. Bots not built yet are listed with built=False so the dashboard
can show them and programs can already exclude their result types."""
from __future__ import annotations

# finding type id -> (label, "finding" | "lead")
DEPARTMENTS: list[dict] = [
    {"id": "recon", "name": "Recon", "summary":
        "Builds the inventory: hosts, DNS, live sites, URLs, parameters, JavaScript files.",
     "bots": [
        {"id": "subdomains", "name": "Subdomain bot", "built": True,
         "does": "Finds subdomains in certificate transparency logs and passive DNS.",
         "types": {}},
        {"id": "dns", "name": "DNS bot", "built": True,
         "does": "Records A, CNAME, MX, TXT and NS records for in-scope names.",
         "types": {}},
        {"id": "livehosts", "name": "Live host bot", "built": True,
         "does": "Checks which in-scope hosts answer over HTTP(S) and what tech they run.",
         "types": {}},
        {"id": "publicfiles", "name": "Public files bot", "built": True,
         "does": "Reads robots.txt, sitemap.xml and security.txt.",
         "types": {}},
        {"id": "crawler", "name": "Crawler bot", "built": True,
         "does": "Browses in-scope sites like a visitor; collects pages, URLs, "
                 "parameters, forms and JavaScript files.",
         "types": {}},
        {"id": "archive", "name": "Archive bot", "built": True,
         "does": "Collects old URLs from the Wayback Machine (never requests them).",
         "types": {"archive_interesting_file": ("Interesting file in web archive", "lead")}},
        {"id": "github", "name": "GitHub bot", "built": True,
         "does": "Searches public GitHub code for the target's domains (needs your token).",
         "types": {"github_secret": ("Possible secret on public GitHub", "finding"),
                   "github_internal_url": ("Internal URL on public GitHub", "lead")}},
        {"id": "buckets", "name": "Bucket bot", "built": True,
         "does": "Notes cloud storage buckets referenced in pages and JavaScript "
                 "(never requests them).",
         "types": {"bucket_reference": ("Cloud storage bucket referenced", "lead")}},
    ]},
    {"id": "headers", "name": "Headers", "summary":
        "Judges headers of responses Recon already stored. Sends no requests.",
     "bots": [
        {"id": "security_headers", "name": "Security headers bot", "built": True,
         "does": "Flags missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
                 "Referrer-Policy and Permissions-Policy.",
         "types": {"missing_csp": ("Missing Content-Security-Policy", "finding"),
                   "missing_hsts": ("Missing Strict-Transport-Security", "finding"),
                   "missing_xfo": ("Missing X-Frame-Options", "finding"),
                   "missing_xcto": ("Missing X-Content-Type-Options", "finding"),
                   "missing_referrer_policy": ("Missing Referrer-Policy", "finding"),
                   "missing_permissions_policy": ("Missing Permissions-Policy", "finding")}},
        {"id": "csp_quality", "name": "CSP quality bot", "built": True,
         "does": "Flags weak CSP (unsafe-inline, wildcards).",
         "types": {"weak_csp": ("Weak Content-Security-Policy", "finding")}},
        {"id": "version_disclosure", "name": "Version disclosure bot", "built": True,
         "does": "Flags versions shown in Server and X-Powered-By.",
         "types": {"version_disclosure": ("Software version disclosed in headers", "finding")}},
        {"id": "cors", "name": "CORS bot", "built": True,
         "does": "Flags CORS that allows any origin with credentials in normal responses.",
         "types": {"cors_permissive": ("Permissive CORS with credentials", "finding")}},
        {"id": "cache", "name": "Cache bot", "built": True,
         "does": "Flags sensitive pages without Cache-Control.",
         "types": {"cache_control_missing": ("Sensitive page without Cache-Control", "finding")}},
        {"id": "clickjacking", "name": "Clickjacking bot", "built": True,
         "does": "Flags pages without framing protection.",
         "types": {"clickjacking": ("Page can be framed (clickjacking)", "finding")}},
    ]},
    {"id": "cookies", "name": "Cookies", "summary": "Judges Set-Cookie headers Recon already stored, redirects included. Sends no requests.",
     "bots": [
        {"id": "cookie_flags", "name": "Cookie flags bot", "built": True,
         "does": "Flags session-like cookies missing Secure, HttpOnly or SameSite.",
         "types": {"cookie_no_secure": ("Cookie without Secure", "finding"),
                   "cookie_no_httponly": ("Cookie without HttpOnly", "finding"),
                   "cookie_no_samesite": ("Cookie without SameSite", "finding")}},
        {"id": "cookie_scope", "name": "Cookie scope bot", "built": True,
         "does": "Flags session-like cookies shared with every subdomain (Domain=parent).",
         "types": {"cookie_broad_domain": ("Cookie scoped to parent domain", "finding")}},
    ]},
    {"id": "tls", "name": "TLS", "summary":
        "One normal TLS handshake per HTTPS endpoint, plus at most two old-version "
        "handshakes. No HTTP requests, no cipher enumeration.",
     "bots": [
        {"id": "certificate", "name": "Certificate bot", "built": True,
         "does": "Flags expired, self-signed, mismatched, untrusted or weak certificates.",
         "types": {"cert_expired": ("Expired certificate", "finding"),
                   "cert_self_signed": ("Self-signed certificate", "finding"),
                   "cert_mismatch": ("Certificate name mismatch", "finding"),
                   "cert_untrusted": ("Untrusted certificate chain", "finding"),
                   "cert_weak": ("Weak certificate signature or key", "finding")}},
        {"id": "protocol", "name": "Protocol bot", "built": True,
         "does": "Flags TLS 1.0/1.1 still accepted and weak or non-forward-secret ciphers.",
         "types": {"tls_outdated": ("Outdated TLS version accepted", "finding"),
                   "tls_weak_cipher": ("Weak cipher negotiated", "finding")}},
        {"id": "https", "name": "HTTPS bot", "built": True,
         "does": "Flags HTTP that doesn't redirect to HTTPS, and mixed content (no requests).",
         "types": {"http_no_redirect": ("HTTP does not redirect to HTTPS", "finding"),
                   "mixed_content": ("Mixed content on HTTPS page", "finding")}},
    ]},
    {"id": "content", "name": "Content and JavaScript", "summary":
        "Reads pages and JavaScript the crawler stored. Only fetches source maps the JavaScript names, and asks OSV.dev about library versions.",
     "bots": [
        {"id": "secrets", "name": "Secrets bot", "built": True,
         "does": "Finds API keys, tokens and secrets in JavaScript.",
         "types": {"js_secret": ("Possible secret in JavaScript", "finding")}},
        {"id": "endpoints", "name": "Endpoint bot", "built": True,
         "does": "Extracts hidden API endpoints, internal hostnames and IPs from JavaScript.",
         "types": {"internal_host_disclosure": ("Internal hostname disclosed", "finding"),
                   "internal_ip_disclosure": ("Internal IP address disclosed", "finding")}},
        {"id": "sourcemaps", "name": "Source map bot", "built": True,
         "does": "Flags source maps that JavaScript references and that are reachable (one GET per referenced map).",
         "types": {"sourcemap_exposed": ("Public JavaScript source map", "finding")}},
        {"id": "debug", "name": "Debug bot", "built": True,
         "does": "Flags debug comments, stack traces and verbose errors in normal responses.",
         "types": {"debug_info": ("Debug information in response", "finding")}},
        {"id": "libraries", "name": "Outdated library bot", "built": True,
         "does": "Identifies JavaScript library versions and looks up known CVEs in OSV.dev.",
         "types": {"outdated_library": ("Library with known CVEs", "finding")}},
    ]},
    {"id": "dns", "name": "DNS and takeover", "summary": "Works on the DNS records and pages Recon collected; a few extra lookups for broken delegations and email policy.",
     "bots": [
        {"id": "takeover", "name": "Takeover bot", "built": True,
         "does": "Flags subdomains pointing to unclaimed third-party services.",
         "types": {"subdomain_takeover": ("Possible subdomain takeover", "finding")}},
        {"id": "dangling_ns", "name": "NS bot", "built": True,
         "does": "Flags in-scope names whose delegation fails (SERVFAIL), a sign of a dangling NS record.",
         "types": {"dangling_ns": ("Dangling NS delegation", "finding")}},
        {"id": "email_security", "name": "Email security bot", "built": True,
         "does": "Flags missing or weak SPF and DMARC. DKIM is not checked (its selectors cannot be found without guessing).",
         "types": {"spf_missing": ("SPF missing", "finding"),
                   "spf_weak": ("Weak SPF", "finding"),
                   "dmarc_missing": ("DMARC missing", "finding"),
                   "dmarc_weak": ("Weak DMARC policy", "finding"),
                   "dkim_missing": ("DKIM not found", "finding")}},
    ]},
    {"id": "thirdparty", "name": "Third-party links", "summary":
        "Checks domains and social profiles the site links to, through domain registries "
        "and public platform APIs. Never visits the linked sites.",
     "bots": [
        {"id": "broken_links", "name": "Broken link bot", "built": True,
         "does": "Flags linked domains that are not registered, expired or being deleted "
                 "(asks the registry over RDAP).",
         "types": {"broken_link_expired_domain": ("Link to expired domain", "finding")}},
        {"id": "social_handles", "name": "Social handle bot", "built": True,
         "does": "Flags linked GitHub/GitLab accounts that don't exist; lists other "
                 "platforms' links for a manual check.",
         "types": {"social_handle_unclaimed": ("Unclaimed social handle", "finding")}},
    ]},
    {"id": "leads", "name": "Leads", "summary": "Flag only, never test: candidates for your manual work. Sends no requests.",
     "bots": [
        {"id": "redirect_leads", "name": "Redirect leads bot", "built": True,
         "does": "Flags url/redirect/next/return-style parameters.",
         "types": {"lead_redirect_param": ("Redirect-style parameter", "lead")}},
        {"id": "xss_leads", "name": "XSS leads bot", "built": True,
         "does": "Flags reflected parameter values, echo-prone parameters and free-text forms.",
         "types": {"lead_xss_param": ("Reflected input worth testing", "lead")}},
    ]},
]


def finding_types() -> dict[str, dict]:
    """type id -> {label, kind, department, bot}"""
    types = {}
    for dept in DEPARTMENTS:
        for bot in dept["bots"]:
            for type_id, (label, kind) in bot["types"].items():
                types[type_id] = {"label": label, "kind": kind,
                                  "department": dept["id"], "bot": bot["id"]}
    return types


def department(dept_id: str) -> dict | None:
    return next((d for d in DEPARTMENTS if d["id"] == dept_id), None)


def public_catalog() -> list[dict]:
    return [{**d, "bots": [{**b, "types": [{"id": t, "label": label, "kind": kind}
                                           for t, (label, kind) in b["types"].items()]}
                           for b in d["bots"]]} for d in DEPARTMENTS]
