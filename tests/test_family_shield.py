"""Run with:  python -m unittest -v"""

import builtins
import collections
import getpass
import hashlib
import io
import os
import random
import string
import tempfile
import unicodedata
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

from family_shield import __main__ as app
from family_shield import checklist, generator, links, passwords, vault

STRONG = "Maple-Owl-Tent-River-Jazz-Pearl-42"


class PasswordTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(passwords.check_strength("password")[0], 0)

    def test_disguised_common_passwords_are_very_weak(self):
        for pw in ("Password1!", "P@ssw0rd123", "adm1n", "Iloveyou2024", "Monkey12345!", "QWERTY"):
            self.assertEqual(passwords.check_strength(pw)[0], 0, pw)

    def test_repetition_is_very_weak(self):
        for pw in ("a" * 1000, "ab" * 10, "Xy1!" * 8):
            self.assertLessEqual(passwords.check_strength(pw)[0], 1, pw)

    def test_short_passwords_are_capped(self):
        self.assertLessEqual(passwords.check_strength("xK9#mQ2$vL")[0], 2)   # 10 chars
        self.assertLessEqual(passwords.check_strength("xK9#mQ2")[0], 1)      # 7 chars

    def test_short_password_flagged(self):
        _, _, problems = passwords.check_strength("Ab3$x")
        self.assertTrue(any("12 characters" in p for p in problems))

    def test_patterns_flagged(self):
        _, _, problems = passwords.check_strength("Rahul1990abcd!!")
        self.assertTrue(any("years" in p for p in problems))
        self.assertTrue(any("runs" in p for p in problems))

    def test_long_passphrases_are_strong(self):
        for pw in (STRONG, "correct horse battery staple"):
            self.assertGreaterEqual(passwords.check_strength(pw)[0], 3, pw)

    def test_empty_password(self):
        self.assertEqual(passwords.check_strength("")[0], 0)

    def test_breach_response_parsing(self):
        full = passwords.sha1_hex("password")
        self.assertEqual(full, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        body = "0000000000000000000000000000000000A:0\r\n" + full[5:] + ":12345\r\n"
        self.assertEqual(passwords.count_in_breach_response(full, body), 12345)
        self.assertEqual(passwords.count_in_breach_response(full, "ABC:1"), 0)
        self.assertEqual(passwords.count_in_breach_response(full, ""), 0)

    def test_breach_lookup_never_sends_the_password(self):
        sent = {}

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def fake_urlopen(request, timeout):
            sent["url"] = request.full_url
            return Response((passwords.sha1_hex("hunter2")[5:] + ":42\r\n").encode())

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            self.assertEqual(passwords.times_seen_in_breaches("hunter2"), 42)
        self.assertTrue(sent["url"].endswith("/range/" + passwords.sha1_hex("hunter2")[:5]))
        self.assertNotIn("hunter2", sent["url"])
        self.assertNotIn(passwords.sha1_hex("hunter2")[5:], sent["url"])

    def test_undecodable_terminal_input_does_not_crash(self):
        self.assertEqual(len(passwords.sha1_hex("ab\udcffcd")), 40)


class GeneratorTests(unittest.TestCase):
    def test_word_list_has_no_duplicates(self):
        self.assertEqual(len(generator.WORDS), len(set(generator.WORDS)))

    def test_shape(self):
        parts = generator.generate_passphrase(word_count=5).split("-")
        self.assertEqual(len(parts), 6)
        self.assertTrue(parts[-1].isdigit())

    def test_entropy_is_reasonable(self):
        self.assertGreater(generator.passphrase_entropy_bits(), 50)

    def test_passphrases_do_not_repeat(self):
        made = {generator.generate_passphrase() for _ in range(2000)}
        self.assertEqual(len(made), 2000)

    def test_generated_passphrases_rate_strong(self):
        for _ in range(200):
            pw = generator.generate_passphrase()
            self.assertGreaterEqual(passwords.check_strength(pw)[0], 3, pw)

    def test_every_word_gets_used_fairly(self):
        counts = collections.Counter(
            generator.generate_passphrase(word_count=10, add_number=False).split("-")[i].lower()
            for _ in range(5000) for i in range(10))
        self.assertEqual(len(counts), len(generator.WORDS))  # nothing is never picked
        expected = 50000 / len(generator.WORDS)
        self.assertLess(max(counts.values()), expected * 1.6)
        self.assertGreater(min(counts.values()), expected * 0.4)


class VaultTests(unittest.TestCase):
    def test_round_trip(self):
        blob = vault.encrypt_bytes(b"Aadhaar: 1234", "correct horse battery")
        self.assertNotIn(b"Aadhaar", blob)
        self.assertEqual(vault.decrypt_bytes(blob, "correct horse battery"), b"Aadhaar: 1234")

    def test_empty_data(self):
        self.assertEqual(vault.decrypt_bytes(vault.encrypt_bytes(b"", "pw"), "pw"), b"")

    def test_same_input_encrypts_differently(self):
        self.assertNotEqual(vault.encrypt_bytes(b"x", "pw"), vault.encrypt_bytes(b"x", "pw"))

    def test_wrong_passphrase(self):
        blob = vault.encrypt_bytes(b"secret", "right")
        for guess in ("wrong", "Right", "right ", ""):
            with self.assertRaises(vault.VaultError):
                vault.decrypt_bytes(blob, guess)

    def test_every_byte_is_tamper_proof(self):
        blob = vault.encrypt_bytes(b"secret", "pw")
        for position in range(len(blob)):
            damaged = bytearray(blob)
            damaged[position] ^= 1
            with self.assertRaises(vault.VaultError, msg=f"byte {position}"):
                vault.decrypt_bytes(bytes(damaged), "pw")

    def test_truncated_files_rejected(self):
        blob = vault.encrypt_bytes(b"secret", "pw")
        for length in range(len(blob)):
            with self.assertRaises(vault.VaultError):
                vault.decrypt_bytes(blob[:length], "pw")

    def test_accented_passphrase_works_across_devices(self):
        blob = vault.encrypt_bytes(b"x", unicodedata.normalize("NFC", "café-mañana"))
        self.assertEqual(vault.decrypt_bytes(blob, unicodedata.normalize("NFD", "café-mañana")), b"x")

    def test_undecodable_terminal_input_does_not_crash(self):
        blob = vault.encrypt_bytes(b"x", "ab\udcffcd")
        self.assertEqual(vault.decrypt_bytes(blob, "ab\udcffcd"), b"x")

    def test_random_garbage_only_raises_vault_error(self):
        rng = random.Random(7)
        for _ in range(100):
            junk = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
            for blob in (junk, vault.MAGIC + junk):
                with self.assertRaises(vault.VaultError):
                    vault.decrypt_bytes(blob, "pw")

    def test_files_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            original = os.path.join(folder, "insurance.pdf")
            with open(original, "wb") as handle:
                handle.write(b"%PDF policy")
            encrypted = vault.encrypt_file(original, "pw")
            with self.assertRaises(vault.VaultError):
                vault.encrypt_file(original, "pw")  # .fsv already exists
            with self.assertRaises(vault.VaultError):
                vault.decrypt_file(encrypted, "pw")  # original still exists
            os.remove(original)
            with self.assertRaises(vault.VaultError):
                vault.decrypt_file(encrypted, "wrong")
            self.assertFalse(os.path.exists(original))  # failed attempt leaves nothing
            restored = vault.decrypt_file(encrypted, "pw")
            with open(restored, "rb") as handle:
                self.assertEqual(handle.read(), b"%PDF policy")

    def test_web_download_name_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            web_file = os.path.join(folder, "policy.pdf.fsv.txt")
            with open(web_file, "wb") as handle:
                handle.write(vault.encrypt_bytes(b"%PDF", "pw"))
            restored = vault.decrypt_file(web_file, "pw")
            self.assertEqual(restored, os.path.join(folder, "policy.pdf"))

    def test_decrypt_requires_fsv_extension(self):
        with self.assertRaises(vault.VaultError):
            vault.decrypt_file("notes.txt", "pw")


class LinkTests(unittest.TestCase):
    def test_real_sites_are_clean(self):
        for url in ("https://www.google.com", "https://www.amazon.co.uk/orders",
                    "https://onlinesbi.sbi", "https://pineapple.com", "google.com",
                    "HTTPS://WWW.GOOGLE.COM", "https://google.com.",
                    "https://www.onlinesbi.sbi/login/account", "https://mail.google.co.in",
                    "https://netbanking.hdfcbank.com", "https://1password.com",
                    "https://www.irctc.co.in", "  https://paypal.me/x  ",
                    # Government, bank and UPI sites the new rules must leave alone
                    "https://uidai.gov.in", "https://eportal.incometax.gov.in", "https://sbi.co.in",
                    "https://www.hdfcbank.com", "https://www.npci.org.in", "https://pay.google.com",
                    "https://www.cybercrime.gov.in", "https://yonobusiness.sbi", "https://kite.zerodha.com",
                    "https://login.microsoftonline.com", "https://www.usa.gov",
                    "https://docs.google.com/document/d/abc/edit"):
            self.assertEqual(links.check_link(url), [], url)

    def test_scam_links_flagged(self):
        for url in ("http://paypal-secure-login.xyz/verify",
                    "https://sbi.kyc-update.top/login",
                    "https://www.amazon.in.offers-today.xyz",
                    "https://secure-login-hdfc.com",
                    "http://192.168.4.20/bank",
                    "http://[::1]/bank",
                    "https://www.google.com@evil.example",
                    "https://bit.ly/abc",
                    "https://xn--pple-43d.com",
                    "https://аpple.com",          # Cyrillic 'а'
                    "http://3232235777/",
                    "http://0x7f000001/",
                    "http://127.1/",
                    "http://0177.0.0.1/",
                    "javascript:alert(1)",
                    "DATA:text/html,<script>"):
            self.assertTrue(links.check_link(url), url)

    def test_indian_scam_patterns_flagged(self):
        cases = {
            # Government impersonation
            "https://uidai-aadhaar-update.com": "government",
            "https://aadhaar-kyc.gov-in.co": "government",
            "https://incometax.gov.in.refund-status.com": "government",
            "https://epfo-claim-status.in": "government",
            "https://pm-kisan-yojana.online/apply": "government",
            # Indian brands, alone or glued to bait words
            "https://irctc-refund.in": "irctc",
            "https://kotak-kyc.in": "kotak",
            "https://free-recharge-jio.in": "jio",
            "https://onlinesbi-kyc.co/verify": "onlinesbi",
            "https://googlepay-reward.in": "google",
            "http://hdfcbank-netbanking.com/login": "hdfc",
            # Free website and form builders
            "https://sites.google.com/view/sbi-kyc-update": "free website",
            "https://forms.gle/AbCdEf": "free website",
            "https://hdfc-netbanking.netlify.app": "free website",
            # Pressure words alone
            "https://electricity-bill-update.in": "pressure words",
            "https://customs-parcel-fee.com": "pressure words",
        }
        for url, expected in cases.items():
            warnings = " ".join(links.check_link(url))
            self.assertIn(expected, warnings, url)

    def test_everyday_words_are_not_brands(self):
        self.assertEqual(links.check_link("https://pineapple-express.com"), [])
        self.assertEqual(links.check_link("https://www.hdfclife.com"), [])

    def test_hindi_digits_are_not_an_ip_address(self):
        warnings = " ".join(links.check_link("http://१२३"))
        self.assertNotIn("IP address", warnings)

    def test_invalid_input(self):
        for url in ("", "   ", "http://[bad", "https://"):
            self.assertEqual(links.check_link(url), ["This doesn't look like a valid web address."], url)

    def test_fuzz_never_crashes(self):
        rng = random.Random(3)
        pieces = ["http://", "https://", "@", "[", "]", ":", "/", "xn--", ".", "-", "0x",
                  "paypal", "%", "\\", "?", "#", "\x00", "а", "é", " ", "::1", ":99999"]
        for _ in range(20000):
            if rng.random() < 0.5:
                url = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 10)))
            else:
                url = "".join(rng.choice(string.printable) for _ in range(rng.randint(0, 40)))
            result = links.check_link(url)
            self.assertIsInstance(result, list)
            passwords.check_strength(url)  # reuse the junk on the password checker too


class ChecklistTests(unittest.TestCase):
    def test_all_yes(self):
        self.assertEqual(checklist.score_answers([True] * len(checklist.QUESTIONS)), (100, []))

    def test_todo_sorted_by_priority(self):
        answers = [False] * len(checklist.QUESTIONS)
        percent, todo = checklist.score_answers(answers)
        self.assertEqual(percent, 0)
        self.assertEqual(len(todo), len(checklist.QUESTIONS))
        weights = [weight for weight, _ in todo]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_critical_items_count_more(self):
        critical = [weight == 3 for _, weight, _ in checklist.QUESTIONS]
        minor = [weight == 1 for _, weight, _ in checklist.QUESTIONS]
        self.assertGreater(checklist.score_answers(critical)[0], checklist.score_answers(minor)[0])

    def test_wrong_number_of_answers(self):
        with self.assertRaises(ValueError):
            checklist.score_answers([True])


class MenuTests(unittest.TestCase):
    """Drive the real menu with scripted typing (input and hidden input)."""

    def run_menu(self, typed, hidden=()):
        typed, hidden = iter(typed), iter(hidden)
        out = io.StringIO()
        with mock.patch.object(builtins, "input", lambda prompt="": next(typed)), \
                mock.patch.object(getpass, "getpass", lambda prompt="": next(hidden)), \
                redirect_stdout(out):
            app.main()
        return out.getvalue()

    def test_encrypt_and_decrypt_through_menu(self):
        with tempfile.TemporaryDirectory() as folder:
            doc = os.path.join(folder, "pan card.jpg")
            with open(doc, "wb") as handle:
                handle.write(b"PAN ABCDE1234F")
            out = self.run_menu(["3", f'"{doc}"', "0"], [STRONG, STRONG])
            self.assertIn("Encrypted copy saved", out)
            os.remove(doc)
            out = self.run_menu(["4", doc + ".fsv", "0"], [STRONG])
            self.assertIn("Restored", out)
            with open(doc, "rb") as handle:
                self.assertEqual(handle.read(), b"PAN ABCDE1234F")

    def test_encrypt_rejects_mismatch_and_weak_passphrases(self):
        with tempfile.TemporaryDirectory() as folder:
            doc = os.path.join(folder, "doc.txt")
            open(doc, "w").close()
            self.assertIn("didn't match", self.run_menu(["3", doc, "0"], [STRONG, "other"]))
            self.assertIn("too weak", self.run_menu(["3", doc, "0"], ["Password1!", "Password1!"]))
            self.assertFalse(os.path.exists(doc + ".fsv"))

    def test_missing_file_is_reported_before_asking_passphrase(self):
        out = self.run_menu(["3", "/no/such/file.pdf", "0"], [])  # no hidden input needed
        self.assertIn("no file found", out)

    def test_wrong_passphrase_through_menu(self):
        with tempfile.TemporaryDirectory() as folder:
            enc = os.path.join(folder, "x.fsv")
            with open(enc, "wb") as handle:
                handle.write(vault.encrypt_bytes(b"x", STRONG))
            self.assertIn("Wrong passphrase", self.run_menu(["4", enc, "0"], ["nope"]))

    def test_password_check_with_offline_breach_service(self):
        offline = mock.patch.object(passwords, "times_seen_in_breaches",
                                    side_effect=urllib.error.URLError("offline"))
        with offline:
            out = self.run_menu(["1", "maybe", "y", "0"], ["P@ssw0rd123"])
        self.assertIn("Very weak", out)
        self.assertIn("Could not reach", out)

    def test_password_check_reports_breach(self):
        with mock.patch.object(passwords, "times_seen_in_breaches", return_value=1234567):
            out = self.run_menu(["1", "y", "0"], ["hunter2"])
        self.assertIn("1,234,567 times", out)

    def test_other_tools_and_bad_choices(self):
        out = self.run_menu(["2", "5", "http://paypal-login.xyz", "abc", "99", "0"])
        self.assertIn("bits of entropy", out)
        self.assertIn("DO NOT open", out)
        self.assertEqual(out.count("number from the menu"), 2)

    def test_checkup_through_menu(self):
        out = self.run_menu(["6"] + ["n"] * len(checklist.QUESTIONS) + ["0"])
        self.assertIn("score: 0%", out)
        self.assertIn("1. [CRITICAL]", out)


if __name__ == "__main__":
    unittest.main()
