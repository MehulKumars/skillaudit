"""Indicator extraction (URLs, domains, IPs, e-mails, wallets) and classification.

KNOWN_BAD lists come from public research (Koi/PAN ClawHavoc, Snyk ToxicSkills,
OpenSourceMalware, VirusTotal, Trend Micro, Unit 42, CrowdStrike, Invariant,
Trail of Bits, HiddenLayer). They were transcribed from write-ups, so treat a
hit as "strongly suspicious, verify", and update them as new campaigns appear.
Research proof-of-concept hosts are tagged separately from threat actors.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Known-bad indicators (offline). Keep lowercase.
# --------------------------------------------------------------------------

KNOWN_BAD_IPS = {
    "91.92.242.30": "ClawHavoc / AMOS shared C2 (Koi, OpenSourceMalware, Trend Micro)",
    "2.26.75.16": "OpenClaw malicious-skill wave, May 2026 (Unit 42)",
    "45.32.150.251": "GlassWorm wave 5 infrastructure",
    "45.32.151.157": "GlassWorm wave 5 infrastructure",
    "70.34.242.255": "GlassWorm wave 5 infrastructure",
}
KNOWN_BAD_DOMAINS = {
    "socifiapp.com": "AMOS exfiltration endpoint (ClawHavoc)",
    "install.app-distribution.net": "Fake setup-wizard lure (ClawHavoc / Trend Micro)",
    "app-distribution.net": "Fake setup-wizard lure (ClawHavoc / Trend Micro)",
    "download.setup-service.com": "Malware download host (ClawHavoc)",
    "setup-service.com": "Malware download host (ClawHavoc)",
    "openclawcli.vercel.app": "ClawHavoc lure page",
    "laosji.net": "money-radar remote referral payload (Unit 42)",
    "letssendit.fun": "letssendit crypto-pooling fraud skill (Unit 42)",
    "giftshop.club": "postmark-mcp rug-pull Bcc exfiltration (Snyk)",
}
RESEARCH_POC_DOMAINS = {
    "clawdhub-skill.com": "Research PoC (O'Reilly poisoned ClawdBot skill, ATLAS CS0049)",
    "openclaw.aisystem.tech": "Research PoC (HiddenLayer OpenClaw C2, ATLAS CS0051)",
    "wuzzi.net": "Research PoC host (Embrace The Red)",
    "internal-artifacts.corp.dev": "Research PoC fake registry (Trail of Bits)",
}
KNOWN_BAD_URL_FRAGMENTS = {
    "glot.io/snippets/hfd3x9ueu5": "ClawHavoc paste-site payload (Unit 42 / Koi)",
    "rentry.co/openclaw-code": "ClawHavoc paste-site payload (Unit 42 / Koi)",
    "github.com/aslaep123/": "Malicious GitHub account distributing AuthTool.zip (ClawHavoc)",
    "github.com/keepcold131/clawdauthenticatortool": "Malicious repo (ClawHavoc)",
    "github.com/hedefbari/openclaw-agent": "Malicious repo referenced by 341 skills (ClawHavoc)",
    "github.com/ddoy233/openclawcli": "Malicious repo (ClawHavoc)",
    "/6x8c0trkp4l9uugo": "ClawHavoc AMOS stage path",
    "/dx2w5j5bka6qkwxi": "ClawHavoc AMOS stage path",
    "/ece0f208u7uqhs6x": "ClawHavoc AMOS stage path",
}
KNOWN_BAD_STRINGS = {
    "phan@giftshop.club": "postmark-mcp hidden Bcc address",
    "jhzhhfomng": "AMOS build tag used in ClawHavoc exfiltration",
    "openclaw-agent.exe": "ClawHavoc VMProtect-packed trojan",
    "openclaw-agent.zip": "ClawHavoc password-protected dropper archive",
    "openclawcli.exe": "ClawHavoc trojan",
    "openclawcli.zip": "ClawHavoc dropper archive",
    "authtool.zip": "ClawHavoc dropper archive",
    "polymarketauthtool": "ClawHavoc dropper",
    "clawdbotsignin.zip": "ClawHavoc dropper archive",
    "6ygcuyfrjkztcayccfba9fscnuvpkgxodxe1mjiszqdj": "GlassWorm Solana wallet",
    "bjveajprskfiingbn4vzvghsgj9kce8ajvtbc9s8o8sc": "GlassWorm Solana wallet",
}
KNOWN_BAD_PACKAGES = {
    "postmark-mcp": "Rug-pulled MCP server (>=1.0.16 Bcc exfiltration)",
    "function-color": "npm package pushed by malicious AGENTS.md (Forever Security)",
    "@iflow-mcp/watercrawl-watercrawl-mcp": "GlassWorm wave 5 malicious MCP server",
    "@aifabrix/miso-client": "GlassWorm wave 5",
    "official334": "SANDWORM_MODE npm worm alias",
    "javaorg": "SANDWORM_MODE npm worm alias",
}
KNOWN_BAD_SHA256 = {
    "79e8f3f7a6113773cdbced2c7329e6dbb2d0b8b3bf5a18c6c97cb096652bc1f2": "ClawHavoc Yahoo Finance skill (VirusTotal)",
    "17703b3d5e8e1fe69d6a6c78a240d8c84b32465fe62bed5610fb29335fe42283": "openclaw-agent.exe (VirusTotal)",
    "1e6d4b0538558429422b71d1f4d724c8ce31be92d299df33a8339e32316e2298": "AMOS macOS final stage (VirusTotal)",
    "998c38b430097479b015a68d9435dc5b98684119739572a4dff11e085881187e": "AMOS macOS second stage (OpenSourceMalware)",
    "34423bc9ab424455863e2e1865f27fc94ebbcdf28a1dbf9fcbb7a49fff30213c": "ClawdBotSignIn.zip",
    "28f65cad91c88d8590f5ac4d65d156f3e84e050b06b3d9686e92f1997ef6c7ea": "openclawcli.exe",
    "e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233": "ClawHavoc first-stage dropper",
    "818aea6143282b352fdfdc0f3ebf77a36e54eb3befb5cad1a355a99ab97c6aa7": "'cluw' stealer (Unit 42)",
    "b30eaed1f7478c28f4ec50d07ed5ef014ffbc4b2bc5a38d689ba9f7abb5e19c2": "omnicogg malicious skill (Unit 42)",
    "b6c7e0bf573b1c7d9d3a05eb08d26579199515b847df984862805f44a7af8007": "Malicious TradingView skill (Unit 42)",
    "ebb73dbb5aac1f6fe1a88e8f26126a1e1aa34c9f3345ad4345189b40d9bf1d1d": "money-radar skill (Unit 42)",
    "f4e41aa269c88bf11a2022701a9cf41e9a186aa1b224d837c31bf34e0b875d0e": "letssendit skill (Unit 42)",
    "881ce5cb124c4d2e814783724cc1388f6a1cbf6eee274c3f3366e77ba3503ad7": "OpenClaw malicious-skill sample (Unit 42)",
    "30f97ae88f8861eeadeb54854d47078724e52e2ef36dd847180663b7f5763168": "OpenClaw malicious sample (1Password)",
}
KNOWN_BAD_SKILL_NAMES = {
    "clawhub1", "clawhubb", "clawhubcli", "clawwhub", "cllawhub", "clawhud", "clawhub-6yr3b",
    "polymarket-traiding-bot", "better-polymarket", "polymarket-all-in-one", "rankaj", "axiom-agent",
    "moltbook-lm8", "moltbookagent", "publish-dist", "omnicogg", "money-radar", "letssendit", "santi-text-game",
    "ai-tradingview-assistant-for-macos", "tradingview-ai-indicator-assistant", "pdfcheck", "wistec-core",
    "polymarketbtc", "polymarketbtcassistant", "youtube-summarize-pro", "solana-wallet-tracker",
}
KNOWN_BAD_SKILL_PREFIXES = ("auto-updater-", "solana-0", "insider-wallets-finder-", "lost-bitcoin-")

# Official vendor install scripts. Piping them to a shell is still remote code execution, but the
# source is well known, so findings are downgraded one level (never suppressed).
KNOWN_INSTALLERS = (
    "raw.githubusercontent.com/homebrew/install/", "sh.rustup.rs", "astral.sh/uv/install", "astral.sh/ruff/install",
    "bun.sh/install", "deno.land/install", "deno.land/x/install", "get.docker.com", "install.python-poetry.org",
    "ollama.com/install.sh", "raw.githubusercontent.com/nvm-sh/nvm/", "get.pnpm.io/install", "claude.ai/install",
    "fnm.vercel.app/install", "sdk.cloud.google.com", "starship.rs/install", "get.volta.sh", "pyenv.run",
    "install.determinate.systems", "nixos.org/nix/install", "dot.net/v1/dotnet-install", "mise.run",
    "tailscale.com/install.sh", "raw.githubusercontent.com/helm/helm/", "deb.nodesource.com", "rpm.nodesource.com",
    "get.sdkman.io", "foundry.paradigm.xyz", "cli.github.com/packages", "raw.githubusercontent.com/ohmyzsh/",
    "community.chocolatey.org/install.ps1", "get.scoop.sh", "astral.sh/uv/", "pixi.sh/install",
)


def is_known_installer(text: str) -> bool:
    low = text.lower()
    return any(k in low for k in KNOWN_INSTALLERS)


# --------------------------------------------------------------------------
# Domain classes
# --------------------------------------------------------------------------

EXFIL_SERVICES = {
    "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "pipedream.com", "beeceptor.com",
    "hookbin.com", "requestcatcher.com", "mockbin.org", "webhook.cool", "postb.in", "ptsv2.com", "ptsv3.com",
    "smee.io", "ultrahook.com", "hooks.zapier.com", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun",
    "oast.me", "interact.sh", "interactsh.com", "burpcollaborator.net", "oastify.com", "canarytokens.com",
    "canarytokens.org", "dnslog.cn", "ceye.io", "dnslog.link", "requestrepo.com", "xss.ht", "bxss.me",
}
WEBHOOK_PATTERNS = (
    (re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I), "discord-webhook"),
    (re.compile(r"api\.telegram\.org/bot", re.I), "telegram-bot-api"),
    (re.compile(r"hooks\.slack\.com/(?:services|workflows|triggers)/", re.I), "slack-webhook"),
    (re.compile(r"outlook\.office\.com/webhook/|\.webhook\.office\.com/", re.I), "teams-webhook"),
    (re.compile(r"script\.google\.com/macros/s/", re.I), "google-apps-script"),
)
PASTE_SITES = {
    "pastebin.com", "paste.ee", "hastebin.com", "hastebin.skyra.pw", "ghostbin.co", "ghostbin.com", "rentry.co",
    "rentry.org", "glot.io", "ix.io", "termbin.com", "dpaste.org", "dpaste.com", "paste.rs", "justpaste.it",
    "controlc.com", "privatebin.net", "pastes.io", "paste2.org", "0bin.net", "katb.in", "snippet.host",
}
FILE_SHARES = {
    "transfer.sh", "file.io", "anonfiles.com", "gofile.io", "catbox.moe", "litterbox.catbox.moe", "0x0.st", "temp.sh",
    "bashupload.com", "mega.nz", "mega.io", "mediafire.com", "wetransfer.com", "sendspace.com", "uguu.se",
    "files.catbox.moe", "filebin.net", "tmpfiles.org", "pixeldrain.com", "dropmefiles.com", "anonymfile.com",
    "oshi.at", "keep.sh",
}
TUNNELS = {
    "ngrok.io", "ngrok-free.app", "ngrok.app", "ngrok.dev", "ngrok-free.dev", "trycloudflare.com", "serveo.net",
    "loca.lt", "localtunnel.me", "localhost.run", "lhr.life", "pinggy.io", "pinggy.link", "bore.pub",
    "playit.gg", "tunnelmole.net", "zrok.io", "devtunnels.ms", "telebit.cloud",
}
DYNAMIC_DNS = {
    "duckdns.org", "no-ip.com", "no-ip.org", "noip.me", "ddns.net", "hopto.org", "zapto.org", "serveftp.com",
    "sytes.net", "myftp.biz", "dynu.net", "freedns.afraid.org", "mooo.com", "dyndns.org", "3utilities.com",
    "servehttp.com", "redirectme.net", "chickenkiller.com", "linkpc.net", "kozow.com", "ooguy.com",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "v.gd", "cutt.ly", "rb.gy", "goo.gl", "shorturl.at", "ow.ly",
    "buff.ly", "rebrand.ly", "t.ly", "tiny.cc", "s.id", "lnkd.in", "bl.ink", "short.io", "shorturl.asia",
    "clck.ru", "qrco.de", "tinyurl.is", "u.to", "x.gd", "urlz.fr",
}
FREE_HOSTING = {
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "glitch.me", "repl.co", "replit.dev", "herokuapp.com",
    "onrender.com", "fly.dev", "github.io", "gitlab.io", "000webhostapp.com", "weebly.com", "firebaseapp.com",
    "web.app", "azurewebsites.net", "blob.core.windows.net", "r2.dev", "surge.sh", "deno.dev", "val.run",
}
CODE_HOSTING_RAW = {
    "raw.githubusercontent.com", "gist.githubusercontent.com", "objects.githubusercontent.com", "gist.github.com",
    "bitbucket.org", "gitlab.com", "codeberg.org", "cdn.jsdelivr.net", "unpkg.com",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "icu", "cyou", "rest", "monster", "buzz",
    "sbs", "cfd", "lol", "quest", "su", "bond", "win", "loan", "work", "country", "kim", "date", "racing",
}
WELL_KNOWN = {
    "anthropic.com", "claude.ai", "claude.com", "openai.com", "github.com", "githubusercontent.com", "python.org",
    "pypi.org", "pythonhosted.org", "npmjs.com", "npmjs.org", "nodejs.org", "microsoft.com", "google.com",
    "googleapis.com", "apple.com", "mozilla.org", "w3.org", "wikipedia.org", "readthedocs.io", "stackoverflow.com",
    "docker.com", "docker.io", "example.com", "example.org", "example.net", "localhost", "schema.org",
    "openxmlformats.org", "modelcontextprotocol.io", "agentskills.io", "creativecommons.org", "apache.org",
    "gnu.org", "opensource.org", "json-schema.org", "yaml.org", "mit.edu", "shields.io", "youtube.com",
    "gstatic.com", "cloudflare.com", "amazonaws.com", "azure.com", "office.com", "live.com", "sentry.io",
    "rust-lang.org", "golang.org", "go.dev", "crates.io", "rubygems.org", "nuget.org", "brew.sh", "debian.org",
    "ubuntu.com", "fedoraproject.org", "kernel.org", "jsdelivr.net", "unpkg.com", "fonts.googleapis.com",
    "huggingface.co", "kaggle.com", "arxiv.org", "doi.org", "x.com", "twitter.com", "linkedin.com",
}

URL_RE = re.compile(r"\b(?:https?|ftp|wss?|file|smb|sftp)://[^\s<>\"'`)\]}|\\^]{2,2000}", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{2,5})?(?![\w.])")
EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}\b")
WALLET_RES = (
    (re.compile(r"\bbc1[ac-hj-np-z02-9]{25,59}\b"), "btc-bech32"),
    (re.compile(r"\b0x[a-fA-F0-9]{40}\b"), "eth-address"),
    (re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"), "xmr-address"),
)
NET_CONTEXT = re.compile(
    r"\b(?:connect|socket|curl|wget|nc|ncat|netcat|http|https|host|server|tcp|udp|ssh|ping|telnet|ftp|"
    r"invoke-webrequest|iwr|fetch|requests|urlopen|dial|remote|c2|callback|beacon|proxy|ip)\b|/dev/tcp", re.I)


def _registered_suffix_match(host: str, domains) -> Optional[str]:
    host = host.lower().rstrip(".")
    parts = host.split(".")
    for i in range(len(parts)):
        cand = ".".join(parts[i:])
        if cand in domains:
            return cand
    return None


def classify_host(host: str, url: str = "") -> List[str]:
    """Return tags describing how suspicious a host / URL is."""
    tags: List[str] = []
    h = (host or "").lower().strip("[]").rstrip(".")
    low_url = (url or "").lower()
    if not h:
        return tags
    try:
        ip = ipaddress.ip_address(h)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
            tags.append("private-ip")
        else:
            tags.append("public-ip")
        if h in KNOWN_BAD_IPS:
            tags.append("known-bad")
        return tags
    except ValueError:
        pass
    if _registered_suffix_match(h, KNOWN_BAD_DOMAINS):
        tags.append("known-bad")
    if _registered_suffix_match(h, RESEARCH_POC_DOMAINS):
        tags.append("research-poc")
    for frag in KNOWN_BAD_URL_FRAGMENTS:
        if frag in low_url:
            tags.append("known-bad")
            break
    for rx, tag in WEBHOOK_PATTERNS:
        if rx.search(low_url):
            tags.append(tag)
    checks = (
        (EXFIL_SERVICES, "exfil-service"), (PASTE_SITES, "paste-site"), (FILE_SHARES, "file-share"),
        (TUNNELS, "tunnel"), (DYNAMIC_DNS, "dynamic-dns"), (SHORTENERS, "url-shortener"),
        (FREE_HOSTING, "free-hosting"), (CODE_HOSTING_RAW, "code-hosting-raw"),
    )
    for domains, tag in checks:
        if _registered_suffix_match(h, domains):
            tags.append(tag)
    if h.endswith(".onion"):
        tags.append("onion")
    if "xn--" in h:
        tags.append("punycode")
    if any(ord(c) > 127 for c in h):
        tags.append("non-ascii-host")
    tld = h.rsplit(".", 1)[-1] if "." in h else ""
    if tld in SUSPICIOUS_TLDS:
        tags.append("suspicious-tld")
    if "/releases/download/" in low_url and "github.com" in h:
        tags.append("github-release-download")
    if _registered_suffix_match(h, WELL_KNOWN) and not tags:
        tags.append("well-known")
    return tags


# Severity mapping per tag (for findings)
TAG_SEVERITY = {
    "known-bad": ("critical", "known-ioc", "Known malicious infrastructure"),
    "discord-webhook": ("high", "exfiltration", "Discord webhook (common exfiltration channel)"),
    "telegram-bot-api": ("high", "exfiltration", "Telegram Bot API (common stealer C2 / exfiltration channel)"),
    "slack-webhook": ("medium", "exfiltration", "Slack incoming webhook"),
    "teams-webhook": ("medium", "exfiltration", "Microsoft Teams webhook"),
    "google-apps-script": ("medium", "exfiltration", "Google Apps Script endpoint (used as free C2/exfil)"),
    "exfil-service": ("high", "exfiltration", "Request-capture / OAST service (data exfiltration)"),
    "paste-site": ("high", "remote-exec", "Paste site (mutable remote payloads; used by ClawHavoc)"),
    "file-share": ("high", "remote-exec", "Anonymous file-sharing host"),
    "tunnel": ("high", "reverse-shell", "Tunnel service (exposes or reaches hosts behind NAT)"),
    "dynamic-dns": ("high", "network", "Dynamic-DNS host (cheap, disposable C2)"),
    "onion": ("high", "network", "Tor hidden service"),
    "public-ip": ("medium", "network", "Raw public IP address instead of a domain"),
    "url-shortener": ("medium", "network", "URL shortener hides the real destination"),
    "punycode": ("medium", "network", "Punycode (possible homograph) domain"),
    "non-ascii-host": ("high", "unicode", "Non-ASCII characters in a hostname (homograph)"),
    "suspicious-tld": ("low", "network", "Frequently abused top-level domain"),
    "github-release-download": ("low", "network", "Downloads a GitHub release asset (verify the publisher)"),
    "free-hosting": ("low", "network", "Free hosting / serverless domain (verify ownership)"),
    "research-poc": ("high", "known-ioc", "Published attack proof-of-concept host"),
    "code-hosting-raw": ("info", "network", "Raw code-hosting URL"),
    "url-credentials": ("medium", "secrets", "Credentials embedded in a URL"),
    "plain-http": ("info", "network", "Unencrypted HTTP"),
    "private-ip": ("info", "network", "Private / loopback IP"),
}


def parse_url(url: str) -> Tuple[str, Optional[int], bool]:
    """Return (host, port, has_userinfo)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        try:
            port = parts.port
        except ValueError:
            port = None
        return host, port, bool(parts.username)
    except ValueError:
        return "", None, False


def clean_url(raw: str) -> str:
    url = raw.rstrip(".,;:!?*_~'\"")
    # balance trailing parenthesis / bracket from markdown
    while url and url[-1] in ")]}>" and url.count(url[-1]) > url.count({")": "(", "]": "[", "}": "{", ">": "<"}[url[-1]]):
        url = url[:-1]
    return url


def extract(text: str) -> Dict[str, List[Tuple[str, int, str]]]:
    """Return {"urls": [(value, offset, line)], "ips": [...], "emails": [...], "wallets": [...]}."""
    import bisect
    out: Dict[str, List[Tuple[str, int, str]]] = {"urls": [], "ips": [], "emails": [], "wallets": []}
    starts: List[int] = []
    ends: List[int] = []
    for m in URL_RE.finditer(text):
        url = clean_url(m.group(0))
        if len(url) < 10:
            continue
        out["urls"].append((url, m.start(), ""))
        starts.append(m.start())
        ends.append(m.start() + len(url))
        if len(starts) >= 20000:
            break

    def in_url(pos: int) -> bool:
        i = bisect.bisect_right(starts, pos) - 1
        return i >= 0 and pos < ends[i]

    for k, m in enumerate(IP_RE.finditer(text)):
        if k >= 20000:
            break
        if not in_url(m.start()):
            out["ips"].append((m.group(0), m.start(), ""))
    for k, m in enumerate(EMAIL_RE.finditer(text)):
        if k >= 20000:
            break
        val = m.group(0)
        if in_url(m.start()):
            continue
        if re.search(r"\.(?:png|jpe?g|gif|svg|webp|js|css|py|md)$", val, re.I):
            continue  # image@2x.png style false positives
        out["emails"].append((val, m.start(), ""))
    for rx, kind in WALLET_RES:
        for m in rx.finditer(text):
            out["wallets"].append((m.group(0), m.start(), kind))
    return out
