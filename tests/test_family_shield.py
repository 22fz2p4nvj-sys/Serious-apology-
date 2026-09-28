"""Run with:  python -m unittest"""

import os
import tempfile
import unittest

from family_shield import checklist, generator, links, passwords, vault


class PasswordTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(passwords.check_strength("password")[0], 0)

    def test_short_password_flagged(self):
        _, _, problems = passwords.check_strength("Ab3$x")
        self.assertTrue(any("12 characters" in p for p in problems))

    def test_patterns_flagged(self):
        _, _, problems = passwords.check_strength("Rahul1990abcd!!")
        self.assertTrue(any("years" in p for p in problems))
        self.assertTrue(any("runs" in p for p in problems))

    def test_long_passphrase_is_strong(self):
        score, _, _ = passwords.check_strength("Maple-Owl-Tent-River-Jazz-Pearl-42")
        self.assertGreaterEqual(score, 3)

    def test_breach_response_parsing(self):
        full = passwords.sha1_hex("password")
        self.assertEqual(full, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        body = "0000000000000000000000000000000000A:0\r\n" + full[5:] + ":12345\r\n"
        self.assertEqual(passwords.count_in_breach_response(full, body), 12345)
        self.assertEqual(passwords.count_in_breach_response(full, "ABC:1"), 0)


class GeneratorTests(unittest.TestCase):
    def test_word_list_has_no_duplicates(self):
        self.assertEqual(len(generator.WORDS), len(set(generator.WORDS)))

    def test_shape(self):
        parts = generator.generate_passphrase(word_count=5).split("-")
        self.assertEqual(len(parts), 6)
        self.assertTrue(parts[-1].isdigit())

    def test_entropy_is_reasonable(self):
        self.assertGreater(generator.passphrase_entropy_bits(), 50)


class VaultTests(unittest.TestCase):
    def test_round_trip(self):
        blob = vault.encrypt_bytes(b"Aadhaar: 1234", "correct horse battery")
        self.assertNotIn(b"Aadhaar", blob)
        self.assertEqual(vault.decrypt_bytes(blob, "correct horse battery"), b"Aadhaar: 1234")

    def test_same_input_encrypts_differently(self):
        self.assertNotEqual(vault.encrypt_bytes(b"x", "pw"), vault.encrypt_bytes(b"x", "pw"))

    def test_wrong_passphrase(self):
        blob = vault.encrypt_bytes(b"secret", "right")
        with self.assertRaises(vault.VaultError):
            vault.decrypt_bytes(blob, "wrong")

    def test_tampering_detected(self):
        blob = bytearray(vault.encrypt_bytes(b"secret", "pw"))
        blob[-5] ^= 1
        with self.assertRaises(vault.VaultError):
            vault.decrypt_bytes(bytes(blob), "pw")

    def test_files_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            original = os.path.join(folder, "insurance.pdf")
            with open(original, "wb") as handle:
                handle.write(b"%PDF policy")
            encrypted = vault.encrypt_file(original, "pw")
            with self.assertRaises(vault.VaultError):
                vault.decrypt_file(encrypted, "pw")  # original still exists
            os.remove(original)
            restored = vault.decrypt_file(encrypted, "pw")
            with open(restored, "rb") as handle:
                self.assertEqual(handle.read(), b"%PDF policy")


class LinkTests(unittest.TestCase):
    def test_real_sites_are_clean(self):
        for url in ("https://www.google.com", "https://www.amazon.co.uk/orders",
                    "https://onlinesbi.sbi", "https://pineapple.com"):
            self.assertEqual(links.check_link(url), [], url)

    def test_scam_links_flagged(self):
        for url in ("http://paypal-secure-login.xyz/verify",
                    "https://sbi.kyc-update.top/login",
                    "http://192.168.4.20/bank",
                    "https://www.google.com@evil.example",
                    "https://bit.ly/abc",
                    "https://xn--pple-43d.com"):
            self.assertTrue(links.check_link(url), url)


class ChecklistTests(unittest.TestCase):
    def test_all_yes(self):
        self.assertEqual(checklist.score_answers([True] * len(checklist.QUESTIONS)), (100, []))

    def test_todo_sorted_by_priority(self):
        answers = [False] * len(checklist.QUESTIONS)
        percent, todo = checklist.score_answers(answers)
        self.assertEqual(percent, 0)
        weights = [weight for weight, _ in todo]
        self.assertEqual(weights, sorted(weights, reverse=True))


if __name__ == "__main__":
    unittest.main()
