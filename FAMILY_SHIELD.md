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

## Use it on the web

The `web/` folder is the same toolkit as a web page: open `web/index.html` in any
browser. Everything runs on your own device; documents and passwords are never
uploaded, and the page's Content Security Policy makes the browser itself block
any request to a server other than the breach service. The web vault handles
files up to 100 MB; use the desktop program for bigger ones. Files locked on the web page unlock in the desktop program, and the
other way round.

**Put it online free with GitHub Pages:** on GitHub, open the repository's
**Settings → Pages**, set *Source* to "Deploy from a branch", pick your main
branch and the `/ (root)` folder, and save. After a minute the site is at
`https://<your-username>.github.io/<repository-name>/web/`.

Run the web tests with Node.js 18+: `node --test web/shield-core.test.js`
(they also check that web and desktop vault files are interchangeable, so they
need Python with `cryptography` installed; set `PYTHON=` to its path if needed).

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

3. Run the tests: `python -m unittest -v` (takes about 25 seconds; the vault
   tests are slow on purpose because each passphrase guess is made expensive).

## How it is tested

The 48 Python tests in `tests/test_family_shield.py` (and 16 matching JavaScript
tests in `web/shield-core.test.js`) are a good way to learn how security
software gets checked. They include:

- **Attack cases:** disguised common passwords (`P@ssw0rd123`), look-alike
  letters (`аpple.com` with a Cyrillic "а"), disguised IP addresses
  (`http://3232235777/`), links hidden behind `@`.
- **Tamper tests:** changing *any single byte* of an encrypted file, or cutting
  it short, must be detected.
- **Privacy test:** the breach lookup must never send the password or its full hash.
- **Fuzzing:** thousands of random junk inputs must never crash a tool.
- **False-alarm tests:** real sites (SBI, HDFC, Google, Amazon) must come out clean.
- **Same answers everywhere:** the web tests run the desktop program too and
  require identical password ratings, link warnings and vault files.

### How well the link checker works

Measured on a held-out set of 44 realistic Indian scam links and 52 real sites,
written before the latest rules were designed (so the rules couldn't be tuned
to pass it): **38 of 44 scams caught (86%), 0 false alarms.** Before those rules
it caught 22 (50%).

It still misses scams with no brand name and only one pressure word, such as
`kbc-lottery-2026.in` or `indiapost-parcel-hold.com`, and number-for-letter
look-alikes such as `amaz0n.in` or `paypa1.com` (see the ideas below).
- **Menu tests:** the whole program is driven with scripted typing, including
  mistakes like mismatched passphrases, wrong file paths and invalid menu choices.

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
- Catch brand-free scams like `kbc-lottery-2026.in`, then measure it on a fresh
  held-out set of links you haven't looked at while writing the rule.
- Build a simple graphical window with `tkinter` so parents can use it.
- Scan your home network to list connected devices (learn `nmap` first).
