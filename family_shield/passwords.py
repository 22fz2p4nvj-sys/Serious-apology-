"""Password strength checking and breach lookup.

Threat: most family accounts get broken into because the password is short,
guessable, or was already leaked in some other website's data breach.

Security ideas you will learn here:
  * Entropy  - a rough measure of how many guesses an attacker needs.
  * Hashing  - turning data into a fixed "fingerprint" that can't be reversed.
  * k-anonymity - asking a server about your password WITHOUT sending it.
"""

import hashlib
import math
import re
import urllib.request

# A tiny sample of the passwords attackers try first. Real attackers use
# lists with millions of entries, so this is only a first filter.
COMMON_PASSWORDS = {
    "123456", "123456789", "12345678", "password", "qwerty", "qwerty123",
    "111111", "123123", "abc123", "password1", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "letmein", "football", "sunshine",
    "princess", "000000", "1234567890", "india123", "passw0rd", "master",
}

SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm", "0123456789")


def character_pool_size(password):
    """How many different characters could appear in each position."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    return pool


def estimate_entropy_bits(password):
    """Entropy = length * log2(pool size). Each extra bit doubles the guesses."""
    pool = character_pool_size(password)
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def has_sequence(password, run=4):
    """Detect runs like 'abcd', '1234' or 'qwer' (forwards or backwards)."""
    lowered = password.lower()
    for seq in SEQUENCES:
        for start in range(len(seq) - run + 1):
            chunk = seq[start:start + run]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def check_strength(password):
    """Return (score 0-4, label, list of problems) for a password."""
    problems = []

    if password.lower() in COMMON_PASSWORDS:
        return 0, "Very weak", ["This is one of the most common passwords in the world."]

    if re.search(r"(.)\1\1", password):
        problems.append("Avoid repeating the same character 3+ times (e.g. 'aaa').")
    if has_sequence(password):
        problems.append("Avoid keyboard or alphabet runs like '1234', 'abcd' or 'qwer'.")
    if re.search(r"(19|20)\d\d", password):
        problems.append("Avoid years - birth years and anniversaries are guessed early.")

    # Patterns make a password much easier to guess than the raw math says.
    bits = estimate_entropy_bits(password) - 10 * len(problems)
    if len(password) < 12:
        problems.append("Use at least 12 characters (a passphrase of 4+ words is easiest).")

    if bits < 28:
        score, label = 0, "Very weak"
    elif bits < 40:
        score, label = 1, "Weak"
    elif bits < 60:
        score, label = 2, "Okay"
    elif bits < 80:
        score, label = 3, "Strong"
    else:
        score, label = 4, "Very strong"
    return score, label, problems


def sha1_hex(password):
    """Hash the password. The same input always gives the same 40-char output."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def count_in_breach_response(full_hash, response_text):
    """Find our hash suffix in the server's list of 'SUFFIX:COUNT' lines."""
    suffix = full_hash[5:]
    for line in response_text.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate == suffix:
            return int(count)
    return 0


def times_seen_in_breaches(password, timeout=10):
    """Ask Have I Been Pwned how often this password appeared in leaks.

    k-anonymity: we only send the FIRST 5 characters of the hash. The server
    replies with every leaked hash starting with those 5 characters (hundreds
    of them), and we check for a match on our own computer. The server never
    learns the password or even its full hash.
    """
    full_hash = sha1_hex(password)
    request = urllib.request.Request(
        "https://api.pwnedpasswords.com/range/" + full_hash[:5],
        # Padding adds fake entries so response size can't hint at the answer.
        headers={"User-Agent": "family-shield", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return count_in_breach_response(full_hash, body)
