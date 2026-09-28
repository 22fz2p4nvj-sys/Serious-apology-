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

# Cheap domain endings that scammers register in bulk.
RISKY_TLDS = {"xyz", "top", "click", "zip", "mov", "icu", "buzz", "live", "rest", "cam"}

# Words scammers stuff into fake addresses to look official.
BAIT_WORDS = {
    "login", "verify", "secure", "account", "update", "kyc", "bank", "wallet",
    "refund", "reward", "prize", "otp", "password", "support", "unlock",
}

# Famous brands attackers imitate, e.g. "paypal-secure-login.xyz".
BRANDS = {
    "paypal", "amazon", "google", "microsoft", "apple", "netflix", "whatsapp",
    "facebook", "instagram", "sbi", "hdfc", "icici", "paytm", "phonepe", "flipkart",
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


def check_link(url):
    """Return a list of warnings. An empty list means no red flags were found."""
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    warnings = []

    if not host:
        return ["This doesn't look like a valid web address."]

    if parsed.scheme != "https":
        warnings.append("Not HTTPS: anything you type could be read in transit.")
    if "@" in parsed.netloc:
        warnings.append("Contains '@': the real site is the part AFTER the @, not before.")
    try:
        ipaddress.ip_address(host)
        warnings.append("Uses a raw IP address instead of a name - real banks never do this.")
    except ValueError:
        pass
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
    for brand in sorted(BRANDS):
        if brand in host_words and domain_name != brand:
            warnings.append(
                f"Mentions '{brand}' but the site actually belongs to '{domain}'."
            )
            break

    bait = sorted(word for word in BAIT_WORDS if word in url.lower())
    if len(bait) >= 2:
        warnings.append("Contains pressure words (" + ", ".join(bait) + ") used in scam links.")

    return warnings
