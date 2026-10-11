"""Suspicious link checker.

Threat: phishing. A message says "Your bank KYC expires today, click here",
and the link leads to a fake site that steals passwords or OTPs. This is the
most common way families lose money online.

Security idea: attackers rely on links that LOOK right at a glance. We check
for the tricks they use. This catches common scams but cannot prove a link is
safe - when in doubt, open the official app or type the address yourself.
"""

import ipaddress
import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly",
}

# Domain endings that reports on abused domains (Spamhaus, Interisle) rank
# highest for scams, because they are cheap or free to register in bulk.
RISKY_TLDS = {
    "xyz", "top", "click", "zip", "mov", "icu", "buzz", "live", "rest", "cam",
    "online", "site", "shop", "info", "cfd", "sbs", "bond", "monster", "lol",
    "quest", "win", "loan", "ga", "tk", "ml", "cf", "gq",
}

# Words scammers stuff into fake addresses to sound urgent or official.
BAIT_WORDS = {
    # account and login pressure
    "login", "verify", "secure", "account", "update", "kyc", "bank", "wallet",
    "otp", "password", "support", "unlock", "alert", "blocked", "suspend",
    "expire", "helpdesk",
    # money bait
    "refund", "reward", "prize", "lottery", "winner", "lucky", "gift", "free",
    "bonus", "cashback", "claim", "recharge", "redeem",
    # bills and deliveries
    "bill", "electricity", "parcel", "customs", "courier", "penalty",
}

# Brands attackers imitate, e.g. "paypal-secure-login.xyz": big global names
# plus India's major banks, UPI apps, telecoms, shopping sites and IRCTC.
BRANDS = {
    "paypal", "amazon", "google", "microsoft", "apple", "netflix", "whatsapp",
    "facebook", "instagram",
    "sbi", "onlinesbi", "yono", "hdfc", "hdfcbank", "icici", "icicibank",
    "axisbank", "kotak", "pnb", "bankofbaroda", "canara", "canarabank",
    "unionbank", "idfc", "yesbank", "indusind",
    "paytm", "phonepe", "googlepay", "gpay", "bhim", "npci", "mobikwik",
    "jio", "airtel", "bsnl", "flipkart", "myntra", "meesho", "irctc", "lic",
}

# Brands that are also everyday words ("pineapple"), so we only match them
# as whole words, never glued inside a longer word.
EVERYDAY_WORD_BRANDS = {"apple"}

# Government services scammers copy ("Aadhaar update", "income tax refund").
# Real Indian government sites always end in .gov.in or .nic.in.
GOVERNMENT_SERVICES = {
    "aadhaar", "aadhar", "uidai", "incometax", "epfo", "pmkisan", "yojana",
    "parivahan", "challan", "passport",
}

# Free website and form builders: anyone can make a page on these in minutes.
FREE_SITE_BUILDERS = {
    "sites.google.com", "forms.gle", "forms.office.com", "web.app",
    "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev", "github.io",
    "gitlab.io", "glitch.me", "000webhostapp.com", "blogspot.com",
    "wixsite.com", "weebly.com", "webflow.io", "ngrok-free.app", "ngrok.io",
    "trycloudflare.com", "replit.app", "onrender.com", "herokuapp.com",
    "square.site", "godaddysites.com", "carrd.co", "mystrikingly.com",
    "jimdosite.com",
}


# Second-level labels used under country endings, as in "amazon.co.uk".
COUNTRY_SECOND_LEVELS = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _registered_domain(host):
    """Rough 'example.com' from 'a.b.example.com' (good enough for hints)."""
    parts = host.split(".")
    keep = 2
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in COUNTRY_SECOND_LEVELS:
        keep = 3
    return ".".join(parts[-keep:])


def _imitated_brand(host_words, domain_name):
    """The brand this address borrows without belonging to it, if any."""
    for brand in sorted(BRANDS):
        if domain_name == brand:
            continue
        if brand in host_words:
            return brand
        # Brand glued to bait, as in "hdfcbank-netbanking.com". Only hyphenated
        # names count, so real sites such as "hdfclife.com" are left alone.
        if (len(brand) >= 4 and brand not in EVERYDAY_WORD_BRANDS
                and "-" in domain_name and brand in domain_name):
            return brand
    return None


def _pretends_to_be_government(host):
    if host.endswith((".gov.in", ".nic.in")):
        return False
    if any(service in host for service in GOVERNMENT_SERVICES):
        return True
    # "gov" as its own word, unless the site is another country's real
    # government site (usa.gov, gov.uk).
    words = set(re.split(r"[.-]", host))
    return bool(words & {"gov", "govt"}) and not re.search(r"(^|\.)gov(\.[a-z]{2})?$", host)


def _on_free_site_builder(host, path):
    if host == "docs.google.com" and path.startswith("/forms"):
        return True
    return any(host == site or host.endswith("." + site) for site in FREE_SITE_BUILDERS)


def check_link(url):
    """Return a list of warnings. An empty list means no red flags were found."""
    url = url.strip()
    if url.lower().startswith(("javascript:", "data:", "file:", "vbscript:")):
        return ["Not a web page at all - this kind of link can run code or open local files."]
    has_scheme = "://" in url
    if not has_scheme:
        url = "https://" + url
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ["This doesn't look like a valid web address."]
    warnings = []

    if not host:
        return ["This doesn't look like a valid web address."]

    if has_scheme and parsed.scheme != "https":
        warnings.append("Not HTTPS: anything you type could be read in transit.")
    if "@" in parsed.netloc:
        warnings.append("Contains '@': the real site is the part AFTER the @, not before.")
    try:
        ipaddress.ip_address(host)
        warnings.append("Uses a raw IP address instead of a name - real banks never do this.")
    except ValueError:
        # Browsers also accept disguised IPs: 3232235777, 0x7f000001, 127.1, 0177.0.0.1
        # [0-9], not \d: \d would also accept Hindi digits like "१२३", which
        # browsers treat as letters, not as a number.
        if all(re.fullmatch(r"0x[0-9a-f]+|[0-9]+", part) for part in host.split(".")):
            warnings.append("Uses a disguised IP address (a number instead of a name).")
    if not host.isascii():
        warnings.append("Uses non-English letters that can imitate real ones (e.g. Cyrillic 'а').")
    if host.startswith("xn--") or ".xn--" in host:
        warnings.append("Uses look-alike international letters (punycode) to imitate a real name.")
    if host in SHORTENERS:
        warnings.append("Shortened link hides the real destination.")
    if host.split(".")[-1] in RISKY_TLDS:
        warnings.append(f"Ends in '.{host.split('.')[-1]}', a domain type often used for scams.")
    if host.count(".") >= 4:
        warnings.append("Has many sub-domains - a common trick to push the real domain out of view.")
    if host.count("-") >= 3:
        warnings.append("Has many hyphens - typical of throwaway scam domains.")

    domain = _registered_domain(host)
    domain_name = domain.split(".")[0]
    # Split "paypal-secure.login.xyz" into words so "pineapple" isn't "apple".
    host_words = set(re.split(r"[.-]", host.rsplit(".", 1)[0]))
    brand = _imitated_brand(host_words, domain_name)
    if brand:
        warnings.append(f"Mentions '{brand}' but the site actually belongs to '{domain}'.")
    if _pretends_to_be_government(host):
        warnings.append(
            "Pretends to be a government service, but real Indian government "
            "sites end in .gov.in or .nic.in."
        )
    if _on_free_site_builder(host, parsed.path):
        warnings.append(
            "Made with a free website or form service - anyone can create a page "
            "like this. Never type bank details, card numbers or OTPs into it."
        )

    # Only the site name matters here: real sites also have "/login" pages.
    bait = sorted(word for word in BAIT_WORDS if word in host)
    if len(bait) >= 2:
        warnings.append("Contains pressure words (" + ", ".join(bait) + ") used in scam links.")

    return warnings
