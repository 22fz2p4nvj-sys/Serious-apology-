/* Family Shield for the browser: the same tools as the Python program in
 * ../family_shield, rewritten in JavaScript so they can run on a web page.
 *
 * Everything here runs on the visitor's own device. Passwords, documents and
 * passphrases are never sent anywhere; the only network request is the
 * breach lookup, which sends just 5 characters of a hash (see below).
 *
 * Vault files are byte-compatible with the Python version: a document locked
 * here can be unlocked by `python -m family_shield`, and the other way round.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("./scrypt.js"), globalThis.crypto);
  } else {
    root.FamilyShield = factory(root.scrypt, root.crypto);
  }
})(this, function (scryptLib, crypto) {
  "use strict";
  const subtle = crypto.subtle;
  const encoder = new TextEncoder();

  /* ---------------------------------------------------------------- *
   * Passwords (mirrors family_shield/passwords.py)
   * ---------------------------------------------------------------- */

  const COMMON_PASSWORDS = new Set([
    "123456", "123456789", "12345678", "password", "qwerty", "qwerty123",
    "111111", "123123", "abc123", "password1", "iloveyou", "admin",
    "welcome", "monkey", "dragon", "letmein", "football", "sunshine",
    "princess", "000000", "1234567890", "india123", "passw0rd", "master",
  ]);

  // Attackers automatically try common swaps like "P@ssw0rd" for "password".
  const LEET_SWAPS = { "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                       "0": "o", "$": "s", "5": "s", "7": "t" };

  const SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm", "0123456789"];

  // Count characters the way people see them (an emoji is one, not two).
  const charLength = (text) => Array.from(text).length;

  function characterPoolSize(password) {
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
    return pool;
  }

  // "aaaa" -> "a" and "abababab" -> "ab": repeating something adds almost nothing.
  function removeRepeats(password) {
    return password.replace(/(.+?)\1+/gu, "$1");
  }

  // Entropy = length * log2(pool size). Each extra bit doubles the guesses.
  function estimateEntropyBits(password) {
    const pool = characterPoolSize(password);
    if (pool === 0) return 0;
    return charLength(removeRepeats(password)) * Math.log2(pool);
  }

  // Catch common passwords even when dressed up, e.g. "P@ssw0rd123!".
  function isCommonPassword(password) {
    const lowered = password.toLowerCase();
    const core = lowered.replace(/[^a-z]+$/, "");
    const unswapped = core.replace(/[@431!0$57]/g, (ch) => LEET_SWAPS[ch]);
    return [lowered, core, unswapped].some((guess) => COMMON_PASSWORDS.has(guess));
  }

  // Detect runs like "abcd", "1234" or "qwer" (forwards or backwards).
  function hasSequence(password, run = 4) {
    const lowered = password.toLowerCase();
    for (const seq of SEQUENCES) {
      for (let start = 0; start + run <= seq.length; start++) {
        const chunk = seq.slice(start, start + run);
        const reversed = chunk.split("").reverse().join("");
        if (lowered.includes(chunk) || lowered.includes(reversed)) return true;
      }
    }
    return false;
  }

  const LABELS = ["Very weak", "Weak", "Okay", "Strong", "Very strong"];

  /** Returns {score 0-4, label, problems[]}. */
  function checkStrength(password) {
    if (isCommonPassword(password)) {
      return { score: 0, label: LABELS[0],
               problems: ["This is (a small twist on) one of the world's most common passwords."] };
    }
    const problems = [];
    if (/(.)\1\1/u.test(password)) problems.push("Avoid repeating the same character 3+ times (e.g. 'aaa').");
    if (hasSequence(password)) problems.push("Avoid keyboard or alphabet runs like '1234', 'abcd' or 'qwer'.");
    if (/(19|20)\d\d/.test(password)) problems.push("Avoid years - birth years and anniversaries are guessed early.");

    // Patterns make a password much easier to guess than the raw math says.
    const bits = estimateEntropyBits(password) - 10 * problems.length;
    const length = charLength(password);
    if (length < 12) problems.push("Use at least 12 characters (a passphrase of 4+ words is easiest).");

    let score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    // Short passwords can be brute-forced whatever characters they use.
    if (length < 8 && score > 1) score = 1;
    else if (length < 12 && score > 2) score = 2;
    return { score, label: LABELS[score], problems };
  }

  async function sha1Hex(text) {
    const digest = await subtle.digest("SHA-1", encoder.encode(text));
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  // Find our hash suffix in the server's list of "SUFFIX:COUNT" lines.
  function countInBreachResponse(fullHash, responseText) {
    const suffix = fullHash.slice(5);
    for (const line of responseText.split(/\r?\n/)) {
      const [candidate, count] = line.trim().split(":");
      if (candidate === suffix) return parseInt(count, 10);
    }
    return 0;
  }

  /* k-anonymity: only the FIRST 5 characters of the hash leave the device. The
   * server answers with every leaked hash starting with them (hundreds), and
   * we look for a match here. `fetchImpl` is swappable so tests can fake it. */
  async function timesSeenInBreaches(password, fetchImpl = root_fetch()) {
    const fullHash = await sha1Hex(password);
    const url = "https://api.pwnedpasswords.com/range/" + fullHash.slice(0, 5);
    let response;
    try {
      // Padding adds fake entries so the reply's size can't hint at the answer.
      response = await fetchImpl(url, { headers: { "Add-Padding": "true" } });
    } catch (paddingRefused) {
      response = await fetchImpl(url);
    }
    if (!response.ok) throw new Error("Breach service answered " + response.status);
    return countInBreachResponse(fullHash, await response.text());
  }

  function root_fetch() {
    return (...args) => fetch(...args);
  }

  /* ---------------------------------------------------------------- *
   * Passphrase generator (mirrors family_shield/generator.py)
   * ---------------------------------------------------------------- */

  const WORDS = `
    able acid aged also area army away baby back ball band bank base bath bear
    beat bell belt best bird blue boat body bone book boot born boss both bowl
    bread brick bush cake calm camp card care cart case cash cave chair chalk
    chess city clay cliff clock cloud coat code coin cold cook cool corn cow
    crab crow cube cup dark data dawn deer desk dish dock door dove duck dust
    eagle earth east echo edge egg elbow elk emu fair farm fern field fig film
    fire fish flag flat flute foam fog food fork fox frog fruit game gate gift
    glass glow goat gold golf grape grass green grid gulf hair hall hand harp
    hawk heart hill home honey hook horn horse house ice idea inch ink iron
    island jam jar jazz jeep jelly jet joke juice kettle key kid king kite
    kiwi knee knot lab lake lamp lane leaf lemon lens lily lime lion list lock
    log loop lunch mango map maple mask meal melon milk mint moon moss moth
    mouse mud nail nest net night noon north nose note nut oak oat ocean olive
    onion orange owl paint palm pan paper park path peach pearl pen piano pie
    pig pilot pine pink pipe plum pond pony pool port pot quiz rabbit rain
    river road robin rock roof rope rose ruby sail salt sand seal seed shell
    ship shoe silk silver sky snow sock sofa song soup star stone sugar sun
    swan table tea tent tiger toast tooth tower train tree tulip van vase
    wave whale wheat wind wolf wood yard year yoga zebra zinc zone
  `.trim().split(/\s+/);

  /* A fair random number below n. Using `random % n` would make some numbers
   * slightly more likely ("modulo bias"), so we throw away values from the
   * uneven top slice and draw again. Python's secrets.randbelow does the same. */
  function randomBelow(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    const buffer = new Uint32Array(1);
    do { crypto.getRandomValues(buffer); } while (buffer[0] >= limit);
    return buffer[0] % n;
  }

  function generatePassphrase(wordCount = 6, separator = "-", addNumber = true) {
    const parts = [];
    for (let i = 0; i < wordCount; i++) {
      const word = WORDS[randomBelow(WORDS.length)];
      parts.push(word[0].toUpperCase() + word.slice(1));
    }
    if (addNumber) parts.push(String(randomBelow(100)));
    return parts.join(separator);
  }

  function passphraseEntropyBits(wordCount = 6, addNumber = true) {
    return wordCount * Math.log2(new Set(WORDS).size) + (addNumber ? Math.log2(100) : 0);
  }

  /* ---------------------------------------------------------------- *
   * Suspicious link checker (mirrors family_shield/links.py)
   * ---------------------------------------------------------------- */

  const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly"]);
  // Endings that reports on abused domains rank highest for scams.
  const RISKY_TLDS = new Set(["xyz", "top", "click", "zip", "mov", "icu", "buzz", "live", "rest", "cam",
    "online", "site", "shop", "info", "cfd", "sbs", "bond", "monster", "lol", "quest", "win", "loan",
    "ga", "tk", "ml", "cf", "gq"]);
  const BAIT_WORDS = [
    "login", "verify", "secure", "account", "update", "kyc", "bank", "wallet", "otp", "password",
    "support", "unlock", "alert", "blocked", "suspend", "expire", "helpdesk",
    "refund", "reward", "prize", "lottery", "winner", "lucky", "gift", "free", "bonus", "cashback",
    "claim", "recharge", "redeem",
    "bill", "electricity", "parcel", "customs", "courier", "penalty"];
  // Big global names plus India's major banks, UPI apps, telecoms, shopping sites and IRCTC.
  const BRANDS = ["paypal", "amazon", "google", "microsoft", "apple", "netflix", "whatsapp",
    "facebook", "instagram",
    "sbi", "onlinesbi", "yono", "hdfc", "hdfcbank", "icici", "icicibank", "axisbank", "kotak", "pnb",
    "bankofbaroda", "canara", "canarabank", "unionbank", "idfc", "yesbank", "indusind",
    "paytm", "phonepe", "googlepay", "gpay", "bhim", "npci", "mobikwik",
    "jio", "airtel", "bsnl", "flipkart", "myntra", "meesho", "irctc", "lic"].sort();
  // Everyday words ("pineapple") are only matched whole, never glued inside a longer word.
  const EVERYDAY_WORD_BRANDS = new Set(["apple"]);
  // Real Indian government sites always end in .gov.in or .nic.in.
  const GOVERNMENT_SERVICES = ["aadhaar", "aadhar", "uidai", "incometax", "epfo", "pmkisan", "yojana",
    "parivahan", "challan", "passport"];
  const FREE_SITE_BUILDERS = ["sites.google.com", "forms.gle", "forms.office.com", "web.app",
    "firebaseapp.com", "netlify.app", "vercel.app", "pages.dev", "github.io", "gitlab.io", "glitch.me",
    "000webhostapp.com", "blogspot.com", "wixsite.com", "weebly.com", "webflow.io", "ngrok-free.app",
    "ngrok.io", "trycloudflare.com", "replit.app", "onrender.com", "herokuapp.com", "square.site",
    "godaddysites.com", "carrd.co", "mystrikingly.com", "jimdosite.com"];
  const COUNTRY_SECOND_LEVELS = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
  const INVALID = ["This doesn't look like a valid web address."];

  function registeredDomain(host) {
    const parts = host.split(".");
    const keep = parts.length >= 3 && parts[parts.length - 1].length === 2 &&
      COUNTRY_SECOND_LEVELS.has(parts[parts.length - 2]) ? 3 : 2;
    return parts.slice(-keep).join(".");
  }

  // The brand this address borrows without belonging to it, if any.
  function imitatedBrand(hostWords, domainName) {
    for (const brand of BRANDS) {
      if (domainName === brand) continue;
      if (hostWords.has(brand)) return brand;
      // Brand glued to bait, as in "hdfcbank-netbanking.com". Only hyphenated
      // names count, so real sites such as "hdfclife.com" are left alone.
      if (brand.length >= 4 && !EVERYDAY_WORD_BRANDS.has(brand) &&
          domainName.includes("-") && domainName.includes(brand)) return brand;
    }
    return null;
  }

  function pretendsToBeGovernment(host) {
    if (host.endsWith(".gov.in") || host.endsWith(".nic.in")) return false;
    if (GOVERNMENT_SERVICES.some((service) => host.includes(service))) return true;
    // "gov" as its own word, unless it is another country's real government site (usa.gov, gov.uk).
    const words = host.split(/[.-]/);
    return (words.includes("gov") || words.includes("govt")) && !/(^|\.)gov(\.[a-z]{2})?$/.test(host);
  }

  function onFreeSiteBuilder(host, path) {
    if (host === "docs.google.com" && path.startsWith("/forms")) return true;
    return FREE_SITE_BUILDERS.some((site) => host === site || host.endsWith("." + site));
  }

  function checkLink(input) {
    let url = String(input).trim();
    if (/^(javascript|data|file|vbscript):/i.test(url)) {
      return ["Not a web page at all - this kind of link can run code or open local files."];
    }
    const hasScheme = url.includes("://");
    if (!hasScheme) url = "https://" + url;

    // The browser's URL parser checks the address is real, but it also quietly
    // rewrites tricky hosts (a Cyrillic letter becomes "xn--...", 3232235777
    // becomes 192.168.1.1). So every check below looks at the host exactly as
    // it was typed, the same way the desktop version does.
    let parsed;
    try { parsed = new URL(url); } catch (notAUrl) { return INVALID; }
    if (!parsed.hostname) return INVALID;
    const typedAuthority = (url.split("://")[1] || "").split(/[/?#]/)[0];
    const host = typedAuthority.split("@").pop().replace(/:\d*$/, "").toLowerCase().replace(/\.+$/, "");
    if (!host) return INVALID;
    const warnings = [];

    if (hasScheme && parsed.protocol !== "https:") {
      warnings.push("Not HTTPS: anything you type could be read in transit.");
    }
    if (typedAuthority.includes("@")) {
      warnings.push("Contains '@': the real site is the part AFTER the @, not before.");
    }
    const normalized = parsed.hostname;
    // A plainly written IP stays the same after the browser reads it; "0177.0.0.1"
    // (octal) or "127.1" get rewritten, which means they were disguised.
    if (normalized.startsWith("[") || (/^\d+\.\d+\.\d+\.\d+$/.test(normalized) && normalized === host)) {
      warnings.push("Uses a raw IP address instead of a name - real banks never do this.");
    } else if (host.split(".").every((part) => /^(0x[0-9a-f]+|\d+)$/.test(part))) {
      warnings.push("Uses a disguised IP address (a number instead of a name).");
    }
    if (/[^\x00-\x7f]/.test(host)) {
      warnings.push("Uses non-English letters that can imitate real ones (e.g. Cyrillic 'а').");
    }
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      warnings.push("Uses look-alike international letters (punycode) to imitate a real name.");
    }
    if (SHORTENERS.has(host)) warnings.push("Shortened link hides the real destination.");
    const tld = host.split(".").pop();
    if (RISKY_TLDS.has(tld)) warnings.push(`Ends in '.${tld}', a domain type often used for scams.`);
    if ((host.match(/\./g) || []).length >= 4) {
      warnings.push("Has many sub-domains - a common trick to push the real domain out of view.");
    }
    if ((host.match(/-/g) || []).length >= 3) warnings.push("Has many hyphens - typical of throwaway scam domains.");

    const domain = registeredDomain(host);
    const domainName = domain.split(".")[0];
    // Split "paypal-secure.login.xyz" into words so "pineapple" isn't "apple".
    const beforeEnding = host.includes(".") ? host.slice(0, host.lastIndexOf(".")) : host;
    const brand = imitatedBrand(new Set(beforeEnding.split(/[.-]/)), domainName);
    if (brand) warnings.push(`Mentions '${brand}' but the site actually belongs to '${domain}'.`);
    if (pretendsToBeGovernment(host)) {
      warnings.push("Pretends to be a government service, but real Indian government sites end in .gov.in or .nic.in.");
    }
    if (onFreeSiteBuilder(host, parsed.pathname)) {
      warnings.push("Made with a free website or form service - anyone can create a page like this. " +
        "Never type bank details, card numbers or OTPs into it.");
    }
    // Only the site name matters here: real sites also have "/login" pages.
    const bait = BAIT_WORDS.filter((word) => host.includes(word)).sort();
    if (bait.length >= 2) warnings.push(`Contains pressure words (${bait.join(", ")}) used in scam links.`);
    return warnings;
  }

  /* ---------------------------------------------------------------- *
   * Family check-up (mirrors family_shield/checklist.py)
   * ---------------------------------------------------------------- */

  const QUESTIONS = [
    ["Does every family member use a DIFFERENT password for email and banking?", 3,
     "Use a password manager (Bitwarden is free) so every account gets its own password."],
    ["Is two-factor authentication (2FA/OTP) turned on for email, banking and WhatsApp?", 3,
     "Turn on 2FA everywhere it is offered; start with email - it can reset every other account."],
    ["Does everyone know that banks, police and couriers never ask for OTPs or PINs on a call?", 3,
     "Agree a family rule: never share an OTP, PIN or screen with anyone who calls you."],
    ["Are phones and laptops updated within a week or two of updates arriving?", 3,
     "Turn on automatic updates; most attacks use holes that updates already fixed."],
    ["Do all phones and laptops have a screen lock (PIN, fingerprint or face)?", 2,
     "Set a 6-digit PIN or better on every device, including the kids' and grandparents'."],
    ["Are important documents (IDs, property, insurance) backed up in two places?", 2,
     "Keep one encrypted copy on a pen drive at home and one in cloud storage (use the vault)."],
    ["Has the home Wi-Fi router's default admin password been changed?", 2,
     "Log in to the router (address is on its sticker), change the admin password, use WPA2/WPA3."],
    ["Are apps only installed from the official Play Store / App Store?", 2,
     "Never install APK files sent over WhatsApp or SMS - they are a common way to steal OTPs."],
    ["Do the children's devices have parental controls or supervised accounts?", 1,
     "Use Google Family Link or Apple Screen Time to control app installs and purchases."],
    ["Are UPI / card transaction limits and SMS alerts set on your bank accounts?", 1,
     "Lower daily UPI and card limits to what you actually need and turn on every alert."],
    ["Does someone review which apps can access location, contacts and SMS?", 1,
     "Every few months, open phone Settings > Privacy and remove permissions apps don't need."],
  ];

  /** answers: array of true/false. Returns {percent, todo: [[weight, advice]]}, most critical first. */
  function scoreAnswers(answers) {
    if (answers.length !== QUESTIONS.length) throw new Error("Need one answer per question.");
    const total = QUESTIONS.reduce((sum, q) => sum + q[1], 0);
    let earned = 0;
    const todo = [];
    QUESTIONS.forEach(([, weight, advice], i) => {
      if (answers[i]) earned += weight; else todo.push([weight, advice]);
    });
    todo.sort((a, b) => b[0] - a[0]);
    return { percent: Math.round((100 * earned) / total), todo };
  }

  /* ---------------------------------------------------------------- *
   * Vault (mirrors family_shield/vault.py)
   *
   * File = "FSV1" + 16-byte salt + Fernet token. Fernet is a published
   * recipe: AES-128-CBC encryption plus an HMAC-SHA256 "seal" that detects
   * any change to the file. The browser's built-in Web Crypto does AES and
   * HMAC; only scrypt (the slow passphrase-to-key step) needs a library.
   * ---------------------------------------------------------------- */

  const MAGIC = encoder.encode("FSV1");
  const SALT_SIZE = 16;

  class VaultError extends Error {}

  // The browser holds the whole file in memory as text while locking it. In
  // testing a 420 MB file crashed it outright, and budget phones have far less
  // room, so bigger files belong in the desktop program.
  const MAX_FILE_BYTES = 100 * 1024 * 1024;
  const MAX_LOCKED_BYTES = MAGIC.length + SALT_SIZE + Math.ceil((MAX_FILE_BYTES + 128) / 3) * 4;
  const TOO_BIG = "Files over 100 MB are too big for the web vault. Use the Family Shield desktop program for them.";

  // Same settings as the Python version (n=2**15, r=8, p=1): slow on purpose.
  async function deriveKey(passphrase, salt, onProgress) {
    const bytes = encoder.encode(passphrase.normalize("NFC"));
    const key = await scryptLib.scrypt(bytes, salt, 32768, 8, 1, 32, onProgress);
    return new Uint8Array(key);
  }

  function base64UrlEncode(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
  }

  function base64UrlDecode(text) {
    if (!/^[A-Za-z0-9_-]*={0,2}$/.test(text) || text.length % 4 !== 0) throw new VaultError("bad token");
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function concat(...arrays) {
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let offset = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
  }

  async function fernetKeys(key) {
    const signing = await subtle.importKey("raw", key.slice(0, 16), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
    const encryption = await subtle.importKey("raw", key.slice(16, 32), "AES-CBC", false, ["encrypt", "decrypt"]);
    return { signing, encryption };
  }

  async function encryptBytes(data, passphrase, onProgress) {
    if (data.length > MAX_FILE_BYTES) throw new VaultError(TOO_BIG);
    const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE)); // fresh salt for every file
    const { signing, encryption } = await fernetKeys(await deriveKey(passphrase, salt, onProgress));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, encryption, data));
    const header = new Uint8Array(9);
    header[0] = 0x80;
    new DataView(header.buffer).setBigUint64(1, BigInt(Math.floor(Date.now() / 1000)));
    const body = concat(header, iv, ciphertext);
    const seal = new Uint8Array(await subtle.sign("HMAC", signing, body));
    return concat(MAGIC, salt, encoder.encode(base64UrlEncode(concat(body, seal))));
  }

  function isVaultFile(blob) {
    return blob.length > MAGIC.length + SALT_SIZE && MAGIC.every((b, i) => blob[i] === b);
  }

  async function decryptBytes(blob, passphrase, onProgress) {
    if (blob.length > MAX_LOCKED_BYTES) throw new VaultError(TOO_BIG);
    if (!isVaultFile(blob)) throw new VaultError("This is not a Family Shield vault file.");
    const wrong = new VaultError("Wrong passphrase, or the file was damaged/tampered with.");
    const salt = blob.slice(MAGIC.length, MAGIC.length + SALT_SIZE);
    let token;
    try {
      token = base64UrlDecode(new TextDecoder("ascii", { fatal: true }).decode(blob.slice(MAGIC.length + SALT_SIZE)));
    } catch (notBase64) { throw wrong; }
    if (token.length < 1 + 8 + 16 + 16 + 32 || token[0] !== 0x80) throw wrong;
    const { signing, encryption } = await fernetKeys(await deriveKey(passphrase, salt, onProgress));
    const body = token.slice(0, token.length - 32);
    const seal = token.slice(token.length - 32);
    // verify() compares in constant time, so timing can't leak the right seal.
    if (!(await subtle.verify("HMAC", signing, seal, body))) throw wrong;
    try {
      return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv: body.slice(9, 25) }, encryption, body.slice(25)));
    } catch (badPadding) { throw wrong; }
  }

  return {
    checkStrength, estimateEntropyBits, isCommonPassword, sha1Hex, countInBreachResponse, timesSeenInBreaches,
    WORDS, generatePassphrase, passphraseEntropyBits, randomBelow,
    checkLink, QUESTIONS, scoreAnswers,
    encryptBytes, decryptBytes, isVaultFile, VaultError, MAX_FILE_BYTES, MAX_LOCKED_BYTES, TOO_BIG,
  };
});
