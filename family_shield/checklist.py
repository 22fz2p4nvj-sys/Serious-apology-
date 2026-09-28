"""Family security check-up.

Most family data is lost not through clever hacking but through a handful of
missing basics. This questionnaire scores the household and produces a
prioritised to-do list. Security professionals call this a "risk assessment".
"""

# (question, weight, advice if the answer is "no")
# Weight 3 = critical, 2 = important, 1 = good practice.
QUESTIONS = [
    ("Does every family member use a DIFFERENT password for email and banking?", 3,
     "Use a password manager (Bitwarden is free) so every account gets its own password."),
    ("Is two-factor authentication (2FA/OTP) turned on for email, banking and WhatsApp?", 3,
     "Turn on 2FA everywhere it is offered; start with email - it can reset every other account."),
    ("Does everyone know that banks, police and couriers never ask for OTPs or PINs on a call?", 3,
     "Agree a family rule: never share an OTP, PIN or screen with anyone who calls you."),
    ("Are phones and laptops updated within a week or two of updates arriving?", 3,
     "Turn on automatic updates; most attacks use holes that updates already fixed."),
    ("Do all phones and laptops have a screen lock (PIN, fingerprint or face)?", 2,
     "Set a 6-digit PIN or better on every device, including the kids' and grandparents'."),
    ("Are important documents (IDs, property, insurance) backed up in two places?", 2,
     "Keep one encrypted copy on a pen drive at home and one in cloud storage (use the vault)."),
    ("Has the home Wi-Fi router's default admin password been changed?", 2,
     "Log in to the router (address is on its sticker), change the admin password, use WPA2/WPA3."),
    ("Are apps only installed from the official Play Store / App Store?", 2,
     "Never install APK files sent over WhatsApp or SMS - they are a common way to steal OTPs."),
    ("Do the children's devices have parental controls or supervised accounts?", 1,
     "Use Google Family Link or Apple Screen Time to control app installs and purchases."),
    ("Are UPI / card transaction limits and SMS alerts set on your bank accounts?", 1,
     "Lower daily UPI and card limits to what you actually need and turn on every alert."),
    ("Does someone review which apps can access location, contacts and SMS?", 1,
     "Every few months, open phone Settings > Privacy and remove permissions apps don't need."),
]


def score_answers(answers):
    """answers: list of booleans in QUESTIONS order. Returns (percent, todo list).

    The to-do list is sorted so the most critical fixes come first.
    """
    if len(answers) != len(QUESTIONS):
        raise ValueError("Need one answer per question.")
    total = sum(weight for _, weight, _ in QUESTIONS)
    earned = 0
    todo = []
    for (question, weight, advice), yes in zip(QUESTIONS, answers):
        if yes:
            earned += weight
        else:
            todo.append((weight, advice))
    todo.sort(key=lambda item: -item[0])
    return round(100 * earned / total), todo
