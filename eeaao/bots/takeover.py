"""DNS and takeover department.

Takeover bot       - no network: matches the CNAMEs Recon recorded and the pages
                     Recon stored against known "unclaimed resource" signs.
                     Never registers or claims anything.
NS bot             - NS lookups only for in-scope names whose lookup failed with
                     SERVFAIL (a broken delegation).
Email security bot - TXT lookups for SPF and _dmarc on in-scope domains.
                     DKIM is not checked: its selectors cannot be discovered
                     without guessing names.
"""
from __future__ import annotations

import re

from .. import db
from .base import Bot, BotContext
from .stored import responses
from .thirdparty import registrable

DEPT = "dns"

# service, CNAME pattern, body fingerprint of an unclaimed resource,
# whether a CNAME that no longer resolves is itself a strong sign
SERVICES = [
    ("GitHub Pages", r"\.github\.io$", r"There isn't a GitHub Pages site here", False),
    ("Heroku", r"\.herokuapp\.com$|\.herokudns\.com$", r"No such app|no-such-app\.html", False),
    ("Amazon S3", r"\.s3[.-][a-z0-9.-]*amazonaws\.com$|\.s3-website[.-]", r"NoSuchBucket|The specified bucket does not exist", False),
    ("Amazon Elastic Beanstalk", r"\.elasticbeanstalk\.com$", None, True),
    ("Microsoft Azure", r"\.azurewebsites\.net$|\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azure-api\.net$|\.azureedge\.net$|\.azurecontainer\.io$|\.azurestaticapps\.net$", r"404 Web Site not found", True),
    ("Google Cloud Storage", r"^c\.storage\.googleapis\.com$", r"NoSuchBucket", False),
    ("Shopify", r"\.myshopify\.com$", r"Sorry, this shop is currently unavailable", False),
    ("Fastly", r"\.fastly\.net$|\.fastlylb\.net$", r"Fastly error: unknown domain", False),
    ("Netlify", r"\.netlify\.app$|\.netlify\.com$", r"Not Found - Request ID", False),
    ("Pantheon", r"\.pantheonsite\.io$", r"The gods are wise", False),
    ("Surge.sh", r"\.surge\.sh$", r"project not found", False),
    ("Tumblr", r"domains\.tumblr\.com$", r"Whatever you were looking for doesn't currently exist at this address", False),
    ("Webflow", r"proxy(?:-ssl)?\.webflow\.com$", r"The page you are looking for doesn't exist or has been moved", False),
    ("Zendesk", r"\.zendesk\.com$", r"Help Center Closed", False),
    ("Ghost", r"\.ghost\.io$", r"Domain error|The thing you were looking for is no longer here", False),
    ("Bitbucket", r"\.bitbucket\.io$", r"Repository not found", False),
    ("ReadMe", r"\.readme\.io$", r"Project doesnt exist\.\.\. yet!", False),
    ("Unbounce", r"unbouncepages\.com$", r"The requested URL was not found on this server", False),
    ("Help Scout", r"\.helpscoutdocs\.com$", r"No settings were found for this company", False),
    ("Strikingly", r"\.s\.strikinglydns\.com$", r"page not found", False),
    ("Agile CRM", r"\.agilecrm\.com$", r"Sorry, this page is no longer available", False),
]
SERVICES = [(n, re.compile(c, re.I), re.compile(b, re.I) if b else None, nx)
            for n, c, b, nx in SERVICES]


# Services where a dangling CNAME cannot be claimed just by registering the
# name: the provider checks domain ownership, or the name is not customer-chosen.
NOT_CLAIMABLE = [
    ("Amazon CloudFront", re.compile(r"\.cloudfront\.net$", re.I),
     "CloudFront distribution names are random and assigned by AWS, and AWS verifies "
     "ownership (a valid certificate for the name) before attaching a custom domain."),
    ("Akamai", re.compile(r"\.(?:akamaiedge|akamai|edgekey|edgesuite|akamaized|akamaihd|akadns)\.net$"
                          r"|\.akamaitechnologies\.com$", re.I),
     "Akamai hostnames (including its akadns.net DNS service) are provisioned under contract "
     "and cannot be registered by outsiders."),
    ("Limelight / Edgio", re.compile(r"\.(?:llnwd|llnwi|llnw|edgecastcdn|edgio|systemcdn)\.net$", re.I),
     "Limelight/Edgio names are assigned by the provider per customer account, not chosen or "
     "registered by the public."),
    ("Fastly (shared)", re.compile(r"\.(?:global|map)\.fastly\.net$|\.fastlylb\.net$", re.I),
     "Fastly's shared hostnames are not claimable; a takeover there needs Fastly's own "
     "'unknown domain' page, which the Takeover bot checks separately."),
    ("Cloudflare", re.compile(r"\.(?:cdn\.cloudflare\.net|cloudflare\.net|cloudflaressl\.com)$", re.I),
     "Cloudflare requires proof of domain control before serving a custom hostname."),
    ("Google (ghs / hosted)", re.compile(r"^ghs\.google(?:hosted)?\.com$", re.I),
     "Google requires domain verification before mapping a custom domain."),
    ("Microsoft 365", re.compile(r"\.(?:outlook\.com|office\.com|lync\.com|protection\.outlook\.com)$", re.I),
     "These are Microsoft service endpoints, not customer-registrable names."),
    ("Salesforce Marketing Cloud", re.compile(r"\.sfmc-marketing\.com$|\.exacttarget\.com$", re.I),
     "The target is provisioned by Salesforce for one customer account."),
]


def _under(name: str, roots: list[str]) -> bool:
    return any(name == r or name.endswith("." + r) for r in roots)


class TakeoverBot(Bot):
    id, department = "takeover", DEPT

    async def run(self, ctx: BotContext) -> None:
        hosts = [a for a in db.get_assets(ctx.program_id, "host")
                 if a["data"].get("cname") and ctx.in_scope_host(a["value"])]
        if not hosts:
            ctx.log("No in-scope host has a CNAME record. Run the Subdomain and DNS bots "
                    "of the Recon department first.")
            ctx.partial = True  # input missing: keep earlier cards
            return
        roots = ctx.guard.seed_domains() + ctx.guard.seed_hosts()
        bodies: dict[str, list] = {}
        for page in responses(ctx):
            host = page.url.split("/")[2].split(":")[0].lower()
            bodies.setdefault(host, []).append(page)
        flagged = stale = 0
        for asset in hosts:
            host, data = asset["value"], asset["data"]
            chain = data["cname"]
            dangling = data.get("resolves") is False
            external = [c for c in chain if not _under(c.lower(), roots)]
            service = next(((name, body, nx) for name, cname, body, nx in SERVICES
                            if any(cname.search(c) for c in chain)), None)
            matched = None
            if service and service[1]:
                for page in bodies.get(host, []):
                    hit = service[1].search(page.text)
                    if hit:
                        matched = (page, hit.group(0))
                        break
            if service and matched:
                severity, why = "medium", f"the page served for this host says “{matched[1]}”"
            elif service and dangling and service[2]:
                severity, why = "medium", "the CNAME target no longer resolves"
            elif dangling and external:
                guarded = next(((n, why_not) for n, pattern, why_not in NOT_CLAIMABLE
                                if any(pattern.search(c) for c in chain)), None)
                if guarded:
                    stale += 1
                    ctx.finding(
                        "subdomain_takeover", key=f"{host}|{chain[-1]}", severity="info",
                        title=f"Stale DNS record: {host} → {guarded[0]} (not claimable by itself)",
                        target=host,
                        detail=f"{host} has a CNAME to {chain[-1]}, which no longer resolves. "
                               f"{guarded[1]} So this is most likely a leftover record, not a "
                               "takeover. It is still worth a line in your notes: leftover "
                               "records point at decommissioned systems.",
                        evidence={"cname_chain": " → ".join([host] + chain), "resolves": False,
                                  "service": guarded[0]})
                    continue
                severity, why = "low", "the CNAME points outside the program's domains and no longer resolves"
            else:
                continue
            flagged += 1
            name = service[0] if service else "an unknown service"
            ctx.finding(
                "subdomain_takeover", key=f"{host}|{chain[-1]}", severity=severity,
                title=f"Possible subdomain takeover: {host} → {name}", target=host,
                detail=f"{host} has a CNAME to {chain[-1]} ({name}) and {why}. If the resource "
                       "is unclaimed, whoever registers it serves content on this subdomain. "
                       "Verify with the service's own documentation. Only claim the resource "
                       "if the program's rules allow a takeover proof of concept, and then "
                       "serve nothing but a harmless marker.",
                evidence={"cname_chain": " → ".join([host] + chain),
                          "resolves": not dangling,
                          "service": name,
                          "fingerprint": matched[1] if matched else None,
                          "seen_in": matched[0].url if matched else None,
                          "status": matched[0].status if matched else None})
        ctx.log(f"{len(hosts)} hosts with CNAMEs checked; {flagged} possible takeovers"
                + (f", {stale} stale records on services that cannot be claimed" if stale else ""))


# =====================================================================
NS_PROVIDERS = re.compile(r"awsdns|azure-dns|googledomains|domaincontrol|digitalocean|linode|"
                          r"nsone|ns1\.|dnsimple|cloudflare|ultradns|dnsmadeeasy|vercel-dns|"
                          r"netlify", re.I)


class DanglingNsBot(Bot):
    id, department = "dangling_ns", DEPT

    async def run(self, ctx: BotContext) -> None:
        broken = [a for a in db.get_assets(ctx.program_id, "dns")
                  if a["data"].get("status") in ("SERVFAIL", "ERROR")
                  and ctx.in_scope_host(a["value"])]
        if not broken:
            ctx.log("No in-scope name failed with SERVFAIL in the last DNS run, so no "
                    "delegation looks broken.")
            return
        for asset in broken:
            host = asset["value"]
            ns = await ctx.dns(host, "NS")
            providers = [n for n in ns.records if NS_PROVIDERS.search(n)]
            ctx.finding(
                "dangling_ns", key=host, severity="low",
                title=f"Delegation for {host} looks broken (SERVFAIL)", target=host,
                detail="Every nameserver failed to answer for this name. That happens when a "
                       "subdomain is delegated to a DNS provider zone that was deleted, which "
                       "can let someone else create the zone and control the subdomain. It can "
                       "also be a DNSSEC or temporary failure. Check with `dig +trace` and the "
                       "provider's documentation before going further.",
                evidence={"last_status": asset["data"].get("status"),
                          "ns_lookup_now": ns.status,
                          "nameservers": ns.records or None,
                          "known_provider": providers or None})
        ctx.log(f"{len(broken)} names with failing delegation")


# =====================================================================
class EmailSecurityBot(Bot):
    id, department = "email_security", DEPT

    async def run(self, ctx: BotContext) -> None:
        # A mail domain is a registrable domain itself (example.com), or any host
        # that receives mail (has MX records). A plain subdomain such as
        # www.example.com is not one: mail "from" it is governed by the parent
        # domain's DMARC policy, so missing records there mean nothing.
        domains = set()
        for name in ctx.guard.seed_domains() + ctx.guard.seed_hosts():
            if registrable(name) == name and ctx.in_scope_host(name):
                domains.add(name)
        stored = {a["value"]: a["data"] for a in db.get_assets(ctx.program_id, "dns")}
        domains.update(h for h, d in stored.items()
                       if d.get("records", {}).get("MX") and ctx.in_scope_host(h))
        if not domains:
            ctx.log("No in-scope mail domain: the scope lists no registrable domain itself "
                    "(only subdomains or IPs), and no in-scope host has MX records.")
            return
        ctx.log("DKIM is not checked: its selector names cannot be discovered without guessing.")
        flagged = 0
        for domain in sorted(domains):
            records = stored.get(domain, {}).get("records", {})
            txt = records.get("TXT")
            if txt is None:
                answer = await ctx.dns(domain, "TXT")
                if answer.status == "NXDOMAIN":
                    continue
                txt = answer.records
            mx = records.get("MX")
            dmarc_answer = await ctx.dns(f"_dmarc.{domain}", "TXT", policy_for=domain)
            spf = [t for t in txt if t.lower().startswith("v=spf1")]
            dmarc = [t for t in dmarc_answer.records if t.lower().replace(" ", "").startswith("v=dmarc1")]
            ctx.asset("email", domain, {"spf": spf or None, "dmarc": dmarc or None, "mx": mx})

            def report(type_, severity, title, detail, extra=""):
                nonlocal flagged
                flagged += 1
                ctx.finding(type_, key=f"{domain}{extra}", severity=severity, title=title,
                            target=domain,
                            detail=detail + " Most programs exclude SPF/DMARC issues unless "
                                            "you can show spoofed mail actually being delivered.",
                            evidence={"domain": domain, "spf": spf or "(none)",
                                      "dmarc": dmarc or "(none)", "mx": mx or "(none seen)"})

            if not spf:
                report("spf_missing", "info", f"No SPF record for {domain}",
                       "Receivers cannot tell which servers may send mail for this domain.")
            elif len(spf) > 1:
                report("spf_weak", "low", f"{domain} has {len(spf)} SPF records",
                       "More than one SPF record is a permanent error: receivers ignore SPF.",
                       "|multiple")
            else:
                qualifier = re.search(r"(?:^|\s)([+?~-]?)all\b", spf[0].lower())
                if qualifier is None and "redirect=" not in spf[0].lower():
                    report("spf_weak", "info", f"SPF for {domain} has no 'all' rule",
                           "Mail from unlisted servers gets a neutral result.", "|noall")
                elif qualifier and qualifier.group(1) in ("", "+"):
                    report("spf_weak", "low", f"SPF for {domain} allows any server (+all)",
                           "Any server on the internet passes SPF for this domain.", "|plusall")
                elif qualifier and qualifier.group(1) == "?":
                    report("spf_weak", "info", f"SPF for {domain} ends in ?all (neutral)",
                           "Unlisted servers get a neutral result, not a failure.", "|neutral")
            if not dmarc:
                report("dmarc_missing", "info", f"No DMARC record for {domain}",
                       "Without DMARC, receivers apply no policy to mail that fails SPF/DKIM "
                       "alignment.")
            else:
                tags = dict(part.strip().split("=", 1) for part in dmarc[0].split(";")
                            if "=" in part)
                tags = {k.strip().lower(): v.strip().lower() for k, v in tags.items()}
                if len(dmarc) > 1:
                    report("dmarc_weak", "low", f"{domain} has {len(dmarc)} DMARC records",
                           "Multiple DMARC records make receivers ignore DMARC.", "|multiple")
                elif tags.get("p") == "none":
                    report("dmarc_weak", "info", f"DMARC for {domain} is monitor-only (p=none)",
                           "Failing mail is reported but still delivered.", "|none")
                elif tags.get("pct", "100") != "100":
                    report("dmarc_weak", "info",
                           f"DMARC for {domain} applies to {tags['pct']}% of mail",
                           "The policy only covers part of failing mail.", "|pct")
        ctx.flush()
        ctx.log(f"{len(domains)} mail domains checked; {flagged} SPF/DMARC results")


BOTS = {bot.id: bot for bot in (TakeoverBot(), DanglingNsBot(), EmailSecurityBot())}
