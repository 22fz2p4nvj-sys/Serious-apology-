"""Menu-driven entry point. Run with:  python -m family_shield"""

import getpass
import urllib.error

from . import checklist, generator, links, passwords, vault

PRIORITY = {3: "CRITICAL", 2: "IMPORTANT", 1: "GOOD IDEA"}


def ask_yes_no(prompt):
    while True:
        answer = input(prompt + " [y/n] ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def check_password():
    # getpass hides what you type so nobody can read it over your shoulder.
    password = getpass.getpass("Type the password to check (hidden): ")
    if not password:
        return
    score, label, problems = passwords.check_strength(password)
    print(f"\nStrength: {label} ({score}/4)")
    for problem in problems:
        print("  - " + problem)

    if ask_yes_no("\nCheck if it appeared in known data breaches? (only a hash prefix is sent)"):
        try:
            count = passwords.times_seen_in_breaches(password)
        except (urllib.error.URLError, OSError) as error:
            print(f"Could not reach the breach service: {error}")
            return
        if count:
            print(f"WARNING: seen {count:,} times in breaches. Stop using it everywhere.")
        else:
            print("Not found in known breaches. (That's good, but not a guarantee.)")


def make_passphrase():
    print("\nHere are 5 options - pick one you like:\n")
    for _ in range(5):
        print("  " + generator.generate_passphrase())
    print(f"\nEach is about {generator.passphrase_entropy_bits():.0f} bits of entropy.")
    print("Tip: use a password manager so you only have to remember ONE of these.")


def encrypt_document():
    path = input("Path of the file to encrypt: ").strip().strip('"')
    passphrase = getpass.getpass("Choose a vault passphrase (hidden): ")
    if getpass.getpass("Type it again: ") != passphrase:
        print("Passphrases didn't match. Nothing was changed.")
        return
    if passwords.check_strength(passphrase)[0] < 3:
        print("That passphrase is too weak for protecting documents. Try option 2 for ideas.")
        return
    try:
        out = vault.encrypt_file(path, passphrase)
    except (OSError, vault.VaultError) as error:
        print(f"Error: {error}")
        return
    print(f"Encrypted copy saved as: {out}")
    print("Open it once with option 4 to confirm it works, THEN delete the original.")
    print("If you forget the passphrase, the file cannot be recovered by anyone.")


def decrypt_document():
    path = input("Path of the .fsv file: ").strip().strip('"')
    passphrase = getpass.getpass("Vault passphrase (hidden): ")
    try:
        out = vault.decrypt_file(path, passphrase)
    except (OSError, vault.VaultError) as error:
        print(f"Error: {error}")
        return
    print(f"Restored: {out}")


def check_link():
    url = input("Paste the link (don't open it!): ").strip()
    warnings = links.check_link(url)
    if not warnings:
        print("No obvious red flags. Still, for banks, use the official app instead.")
        return
    print(f"\n{len(warnings)} red flag(s) - DO NOT open this link:")
    for warning in warnings:
        print("  - " + warning)


def family_checkup():
    print("\nAnswer honestly for your whole household.\n")
    answers = [ask_yes_no(question) for question, _, _ in checklist.QUESTIONS]
    percent, todo = checklist.score_answers(answers)
    print(f"\nFamily security score: {percent}%")
    if not todo:
        print("Excellent - keep it up and re-check every few months.")
        return
    print("\nYour to-do list, most important first:")
    for number, (weight, advice) in enumerate(todo, 1):
        print(f"  {number}. [{PRIORITY[weight]}] {advice}")


MENU = [
    ("Check a password's strength and breaches", check_password),
    ("Generate a strong, memorable passphrase", make_passphrase),
    ("Encrypt a family document", encrypt_document),
    ("Decrypt a family document", decrypt_document),
    ("Check a suspicious link", check_link),
    ("Family security check-up", family_checkup),
]


def main():
    print("=" * 50)
    print(" FAMILY SHIELD - protect your family's data")
    print("=" * 50)
    while True:
        print()
        for number, (label, _) in enumerate(MENU, 1):
            print(f"  {number}. {label}")
        print("  0. Exit")
        choice = input("\nChoose an option: ").strip()
        if choice == "0":
            print("Stay safe!")
            return
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            try:
                MENU[int(choice) - 1][1]()
            except (KeyboardInterrupt, EOFError):
                print("\nCancelled.")
        else:
            print("Please type a number from the menu.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nStay safe!")
