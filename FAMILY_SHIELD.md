# Family Shield

A beginner's cyber security project: simple tools that protect a middle-class
family's data. Every file is commented to explain the security idea behind it,
so reading the code is part of learning.

## What it protects against

| Threat (what really happens to families) | Tool | File |
|---|---|---|
| Weak, reused or already-leaked passwords | Password checker + breach lookup | `family_shield/passwords.py` |
| "I can't remember strong passwords" | Passphrase generator | `family_shield/generator.py` |
| Lost phone/laptop leaks Aadhaar, PAN, bank & medical papers | Encrypted document vault | `family_shield/vault.py` |
| Fake "KYC expiring / prize / refund" links (phishing) | Suspicious link checker | `family_shield/links.py` |
| Missing basics (2FA, updates, OTP sharing, backups) | Family security check-up | `family_shield/checklist.py` |

## How to run it

1. Install Python 3.9 or newer from <https://www.python.org/downloads/>
   (on Windows, tick **"Add Python to PATH"** during install).
2. Open a terminal in this folder and run:

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Mac / Linux:  source .venv/bin/activate
pip install -r requirements.txt
python -m family_shield
```

3. Run the tests: `python -m unittest`

## Important safety notes

- **Vault passphrase:** if you forget it, the encrypted file is gone forever.
  That's what makes it secure. Write it down and keep it somewhere physically safe.
- **After encrypting**, decrypt once to confirm it works before deleting the original.
- The **link checker** catches common tricks but can't prove a link is safe.
  For banks, always use the official app or type the address yourself.
- The **breach lookup** sends only the first 5 characters of your password's
  SHA-1 hash, never the password itself (see comments in `passwords.py`).

## Your learning roadmap (starting from zero)

Work through these in order. Each one connects to a part of this project.

1. **Python basics** (2–4 weeks): variables, functions, loops, files.
   Read `checklist.py` first; it's the simplest file.
2. **How the internet works**: IP addresses, DNS, HTTP vs HTTPS, URLs.
   Then `links.py` will make complete sense.
3. **Cryptography basics**: hashing vs encryption, salts, keys.
   Study `passwords.py` (hashing) and `vault.py` (encryption).
4. **Linux command line**: free game at <https://overthewire.org/wargames/bandit/>.
5. **Structured beginner courses**: TryHackMe "Pre-Security" path,
   Google Cybersecurity Certificate (Coursera), Professor Messer's free CompTIA
   Security+ videos.
6. **Practice legally**: TryHackMe, Hack The Box, picoCTF. Only ever test
   systems you own or have written permission to test.

## Ideas to extend this project as you learn

- Add a "has my email been in a breach?" check (needs a Have I Been Pwned API key).
- Encrypt a whole folder at once instead of one file.
- Detect look-alike domains such as `amaz0n.com` or `paypa1.com`.
- Build a simple graphical window with `tkinter` so parents can use it.
- Scan your home network to list connected devices (learn `nmap` first).
