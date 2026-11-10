"""Pure functions that read text: no network here. Shared by several bots."""
from __future__ import annotations

import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urldefrag, urljoin, urlsplit, urlunsplit

# ---------- URLs ----------

def normalize_url(url: str) -> str | None:
    """Absolute http(s) URL without fragment, lower-case scheme and host."""
    url, _ = urldefrag(url.strip())
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    if re.search(r"[\s\x00-\x1f\\]", url):
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    default = {"http": 80, "https": 443}[parts.scheme.lower()]
    netloc = host if port in (None, default) else f"{host}:{port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def param_names(url: str) -> list[str]:
    return list(dict.fromkeys(name for name, _ in
                              parse_qsl(urlsplit(url).query, keep_blank_values=True) if name))


def endpoint(url: str) -> str:
    """URL without query string: the thing parameters belong to."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


# ---------- HTML ----------

class _PageParser(HTMLParser):
    LINK_ATTRS = {"a": "href", "area": "href", "link": "href", "iframe": "src",
                  "frame": "src", "script": "src", "img": "src", "source": "src",
                  "embed": "src", "object": "data"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []   # (tag, raw url)
        self.scripts: list[str] = []
        self.forms: list[dict] = []
        self.title = ""
        self.generator = ""
        self.base = None
        self.meta_csp: list[str] = []
        self.meta_referrer = ""
        self._in_title = False
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        attrs = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and attrs.get("href") and self.base is None:
            self.base = attrs["href"]
        attr = self.LINK_ATTRS.get(tag)
        if attr and attrs.get(attr):
            self.links.append((tag, attrs[attr]))
            if tag == "script":
                self.scripts.append(attrs[attr])
        if tag == "meta":
            if attrs.get("name", "").lower() == "generator":
                self.generator = attrs.get("content", "")[:200]
            if attrs.get("http-equiv", "").lower() == "content-security-policy":
                self.meta_csp.append(attrs.get("content", "")[:5000])
            if attrs.get("name", "").lower() == "referrer":
                self.meta_referrer = attrs.get("content", "")[:100]
            if attrs.get("http-equiv", "").lower() == "refresh":
                match = re.search(r"url\s*=\s*['\"]?([^'\";]+)", attrs.get("content", ""), re.I)
                if match:
                    self.links.append(("meta", match.group(1)))
        if tag == "title":
            self._in_title = True
        if tag == "form":
            self._form = {"action": attrs.get("action", ""),
                          "method": (attrs.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        if tag in ("input", "select", "textarea", "button") and self._form is not None:
            name = attrs.get("name")
            if name:
                self._form["inputs"].append(
                    {"name": name[:100], "type": (attrs.get("type") or tag).lower()[:30]})

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title and len(self.title) < 200:
            self.title += data


def parse_html(html: str, page_url: str) -> dict:
    parser = _PageParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # broken markup: keep whatever was parsed
        pass
    base = urljoin(page_url, parser.base) if parser.base else page_url
    links = []
    for tag, raw in parser.links:
        if raw.strip().lower().startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        absolute = normalize_url(urljoin(base, raw))
        if absolute:
            links.append((tag, absolute))
    forms = []
    for form in parser.forms:
        action = normalize_url(urljoin(base, form["action"] or page_url))
        if action:
            forms.append(dict(form, action=action))
    scripts = [u for t, u in links if t == "script"]
    return {"title": " ".join(parser.title.split())[:200], "generator": parser.generator,
            "links": links, "scripts": scripts, "forms": forms,
            "meta_csp": parser.meta_csp, "meta_referrer": parser.meta_referrer}


# Paths a polite visitor would not click while browsing anonymously.
UNSAFE_LINK = re.compile(r"log-?out|sign-?out|delete|remove|unsubscribe|destroy|"
                         r"/cancel|deactivate", re.I)
SKIP_EXT = re.compile(r"\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|mp[34]|m4a|wav|ogg|webm|"
                      r"mov|avi|pdf|zip|gz|tgz|rar|7z|tar|exe|msi|dmg|iso|apk|woff2?|ttf|"
                      r"otf|eot|css|docx?|xlsx?|pptx?)$", re.I)


# ---------- technology fingerprints ----------

_HEADER_TECH = [
    ("server", re.compile(r"^(nginx|apache|microsoft-iis|openresty|caddy|litespeed|"
                          r"envoy|gunicorn|cowboy|jetty|tomcat|kestrel)(?:/([\w.]+))?", re.I)),
    ("x-powered-by", re.compile(r"^(php|asp\.net|express|next\.js|servlet|plesk)(?:[/ ]([\w.]+))?",
                                re.I)),
    ("x-aspnet-version", re.compile(r"^([\d.]+)$")),
]
_HEADER_MARKERS = {
    "cf-ray": "Cloudflare", "x-amz-cf-id": "Amazon CloudFront", "x-vercel-id": "Vercel",
    "x-github-request-id": "GitHub Pages", "x-served-by": "Fastly (likely)",
    "x-azure-ref": "Azure Front Door", "x-goog-generation": "Google Cloud Storage",
    "x-amz-request-id": "Amazon S3/AWS", "x-nf-request-id": "Netlify",
    "x-drupal-cache": "Drupal", "x-shopify-stage": "Shopify", "x-wix-request-id": "Wix",
    "x-akamai-transformed": "Akamai", "x-iinfo": "Imperva", "x-sucuri-id": "Sucuri",
}
_COOKIE_TECH = {"phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
                "laravel_session": "Laravel", "csrftoken": "Django (likely)",
                "_rails_session": "Ruby on Rails", "ci_session": "CodeIgniter",
                "wordpress_": "WordPress", "connect.sid": "Express"}
_BODY_TECH = [
    (re.compile(r"/wp-content/|/wp-includes/"), "WordPress"),
    (re.compile(r"__NEXT_DATA__|/_next/static/"), "Next.js"),
    (re.compile(r"__NUXT__|/_nuxt/"), "Nuxt"),
    (re.compile(r"ng-version=\"([\d.]+)\""), "Angular"),
    (re.compile(r"data-reactroot|react-dom"), "React"),
    (re.compile(r"Drupal\.settings|/sites/default/files/"), "Drupal"),
    (re.compile(r"cdn\.shopify\.com"), "Shopify"),
    (re.compile(r"/static/js/main\.[0-9a-f]+\.js"), "Create React App"),
    (re.compile(r"jquery[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.js", re.I), "jQuery"),
    (re.compile(r"bootstrap[.-]([\d]+\.[\d]+\.[\d]+)(?:\.min)?\.(?:js|css)", re.I), "Bootstrap"),
    (re.compile(r"gtag\(|googletagmanager\.com"), "Google Tag Manager"),
]


def fingerprint(headers: list[tuple[str, str]], body: str, generator: str = "") -> list[str]:
    found: dict[str, None] = {}
    lower = [(k.lower(), v) for k, v in headers]
    for name, value in lower:
        for header, pattern in _HEADER_TECH:
            if name == header:
                match = pattern.match(value.strip())
                if match:
                    if header == "x-aspnet-version":
                        label, version = "ASP.NET", match.group(1)
                    else:
                        label, version = match.group(1), match.group(2)
                    found[f"{label} {version}" if version else label] = None
        if name in _HEADER_MARKERS:
            found[_HEADER_MARKERS[name]] = None
        if name == "set-cookie":
            cookie = value.split("=", 1)[0].strip().lower()
            for prefix, tech in _COOKIE_TECH.items():
                if cookie.startswith(prefix):
                    found[tech] = None
    if generator:
        found[generator] = None
    sample = body[:300_000]
    for pattern, tech in _BODY_TECH:
        match = pattern.search(sample)
        if match:
            version = match.group(1) if match.groups() else None
            found[f"{tech} {version}" if version else tech] = None
    return list(found)


# ---------- secrets (GitHub bot now; Secrets bot later) ----------

SECRET_PATTERNS = [
    ("AWS access key ID", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", "medium", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("GitHub token", "high", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("Slack token", "high", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", "medium", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("Stripe live secret key", "high", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")),
    ("Private key block", "high", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY")),
    ("SendGrid API key", "high", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("Twilio API key", "medium", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("Mailgun API key", "medium", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
    ("Google OAuth client secret", "high", re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{28}\b")),
    ("npm token", "high", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("OpenAI API key", "high", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API key", "high", re.compile(r"\bsk-ant-(?:api|admin)\d\d-[A-Za-z0-9_-]{80,}\b")),
    ("JSON Web Token", "low", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Hard-coded credential", "low", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\b[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,120})[\"']")),
]
_PLACEHOLDER = re.compile(r"(?i)x{4,}|\*{3,}|example|changeme|your[_-]|<[a-z_]+>|\$\{|%s|"
                          r"process\.env|placeholder|dummy|test1234|password123")


def mask(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:2] + "…" + secret[-2:]
    return secret[:6] + "…" + secret[-4:]


def find_secrets(text: str) -> list[dict]:
    """[{label, severity, masked, raw}] with placeholders dropped."""
    found, seen = [], set()
    for label, severity, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if match.groups() else match.group(0)
            if value in seen or _PLACEHOLDER.search(value):
                continue
            seen.add(value)
            found.append({"label": label, "severity": severity,
                          "masked": mask(value), "raw": value})
    return found


# ---------- internal references ----------

_INTERNAL_LABEL = re.compile(r"(?:^|[.-])(internal|intranet|corp|private|dev|devel|staging|"
                             r"stage|stg|uat|qa|test|preprod|sandbox|admin|vpn|jenkins|jira|"
                             r"confluence|gitlab|grafana|kibana|k8s|kube)(?:[.-]|$)")
_HOSTNAME = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.I)


def hostnames_under(text: str, domain: str) -> list[str]:
    domain = domain.lower()
    hosts = {h.lower() for h in _HOSTNAME.findall(text)}
    return sorted(h for h in hosts if h == domain or h.endswith("." + domain))


def looks_internal(host: str) -> bool:
    return bool(_INTERNAL_LABEL.search(host.lower())) or host.lower().endswith(
        (".local", ".internal", ".corp", ".lan", ".intranet"))


def is_private_ip(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).is_private
    except ValueError:
        return False


# ---------- cloud storage buckets ----------

BUCKET_PATTERNS = [
    ("Amazon S3", re.compile(r"\b([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com", re.I)),
    # Path style only when nothing precedes "s3", so that in
    # "bucket.s3.amazonaws.com/key" the object key is not read as a bucket.
    ("Amazon S3", re.compile(r"(?<![a-z0-9.-])s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", re.I)),
    ("Amazon S3", re.compile(r"\bs3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", re.I)),
    ("Google Cloud Storage", re.compile(r"\bstorage\.googleapis\.com/([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])", re.I)),
    ("Google Cloud Storage", re.compile(r"\b([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])\.storage\.googleapis\.com", re.I)),
    ("Google Cloud Storage", re.compile(r"\bgs://([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])", re.I)),
    ("Firebase Storage", re.compile(r"\bfirebasestorage\.googleapis\.com/v0/b/([a-z0-9.-]+)", re.I)),
    ("Azure Blob Storage", re.compile(r"\b([a-z0-9]{3,24})\.blob\.core\.windows\.net(?:/([a-z0-9-]{3,63}))?", re.I)),
    ("DigitalOcean Spaces", re.compile(r"\b([a-z0-9-]{3,63})\.([a-z0-9]+)\.digitaloceanspaces\.com", re.I)),
]
_NOT_BUCKET = {"www", "s3", "assets", "static", "cdn", "images", "media"}  # common false hits


def find_buckets(text: str) -> list[tuple[str, str, str]]:
    """[(provider, bucket name, matched text)]"""
    found, seen = [], set()
    for provider, pattern in BUCKET_PATTERNS:
        for match in pattern.finditer(text):
            name = match.group(1).lower()
            if provider == "Azure Blob Storage" and match.lastindex == 2 and match.group(2):
                name = f"{name}/{match.group(2).lower()}"
            if provider == "Amazon S3" and name.startswith("s3") and "." not in name:
                continue
            if name in _NOT_BUCKET or (provider, name) in seen:
                continue
            seen.add((provider, name))
            found.append((provider, name, match.group(0)[:200]))
    return found
