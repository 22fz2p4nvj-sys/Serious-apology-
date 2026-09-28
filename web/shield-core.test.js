// Run with:  node --test web/shield-core.test.js
// The same attack cases as tests/test_family_shield.py, so both versions agree.
const test = require("node:test");
const assert = require("node:assert");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const FS = require("./shield-core.js");

const STRONG = "Maple-Owl-Tent-River-Jazz-Pearl-42";
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);

test("passwords: common and disguised common passwords are very weak", () => {
  for (const pw of ["password", "Password1!", "P@ssw0rd123", "adm1n", "Iloveyou2024", "Monkey12345!", "QWERTY", ""]) {
    assert.strictEqual(FS.checkStrength(pw).score, 0, pw);
  }
});

test("passwords: repetition, short length and patterns", () => {
  for (const pw of ["a".repeat(1000), "ab".repeat(10), "Xy1!".repeat(8)]) assert.ok(FS.checkStrength(pw).score <= 1, pw);
  assert.ok(FS.checkStrength("xK9#mQ2$vL").score <= 2);
  assert.ok(FS.checkStrength("xK9#mQ2").score <= 1);
  const problems = FS.checkStrength("Rahul1990abcd!!").problems.join(" ");
  assert.match(problems, /years/);
  assert.match(problems, /runs/);
});

test("passwords: long passphrases are strong", () => {
  for (const pw of [STRONG, "correct horse battery staple"]) assert.ok(FS.checkStrength(pw).score >= 3, pw);
});

test("passwords: same rating as the Python version for many inputs", () => {
  const samples = ["password", "Password1!", "P@ssw0rd123", "Summer2024!!", "Tr0ub4dour&3", STRONG, "xK9#mQ2$vL",
    "correct horse battery staple", "a".repeat(50), "Rahul1990abcd!!", "hunter2", "пароль-очень-длинный-секрет",
    "zxcvbnm123456", "MyDogIsCalledBruno", "1qaz2wsx3edc", "!!!!!!!!!!!!", "Ab3$x"];
  const script = "import json,sys\nfrom family_shield import passwords as p\n" +
    "print(json.dumps([p.check_strength(s)[0] for s in json.load(sys.stdin)]))";
  const python = JSON.parse(execFileSync(process.env.PYTHON || "python3", ["-c", script],
    { input: JSON.stringify(samples), cwd: path.join(__dirname, "..") }).toString());
  assert.deepStrictEqual(samples.map((s) => FS.checkStrength(s).score), python);
});

test("breach: hash, response parsing and privacy", async () => {
  assert.strictEqual(await FS.sha1Hex("password"), "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
  const full = await FS.sha1Hex("hunter2");
  const seen = [];
  const fakeFetch = async (url) => { seen.push(url); return { ok: true, text: async () => `ABC:1\r\n${full.slice(5)}:42\r\n` }; };
  assert.strictEqual(await FS.timesSeenInBreaches("hunter2", fakeFetch), 42);
  assert.strictEqual(seen[0], "https://api.pwnedpasswords.com/range/" + full.slice(0, 5));
  assert.ok(!seen[0].includes("hunter2") && !seen[0].includes(full.slice(5)));
  assert.strictEqual(FS.countInBreachResponse(full, ""), 0);
});

test("breach: retries without padding header, reports server errors", async () => {
  let calls = 0;
  const refusesHeader = async (url, options) => {
    calls++;
    if (options) throw new TypeError("CORS preflight refused");
    return { ok: true, text: async () => "" };
  };
  assert.strictEqual(await FS.timesSeenInBreaches("x", refusesHeader), 0);
  assert.strictEqual(calls, 2);
  await assert.rejects(FS.timesSeenInBreaches("x", async () => ({ ok: false, status: 503 })), /503/);
});

test("generator: shape, uniqueness, strength and fairness", () => {
  assert.strictEqual(FS.WORDS.length, 270);
  assert.strictEqual(new Set(FS.WORDS).size, 270);
  const parts = FS.generatePassphrase(5).split("-");
  assert.strictEqual(parts.length, 6);
  assert.match(parts[5], /^\d+$/);
  const made = new Set(Array.from({ length: 2000 }, () => FS.generatePassphrase()));
  assert.strictEqual(made.size, 2000);
  for (const pw of Array.from(made).slice(0, 200)) assert.ok(FS.checkStrength(pw).score >= 3, pw);
  assert.ok(FS.passphraseEntropyBits() > 50);
  const counts = new Array(270).fill(0);
  for (let i = 0; i < 100000; i++) counts[FS.randomBelow(270)]++;
  const expected = 100000 / 270;
  assert.ok(Math.max(...counts) < expected * 1.3 && Math.min(...counts) > expected * 0.7);
});

const CLEAN = ["https://www.google.com", "https://www.amazon.co.uk/orders", "https://onlinesbi.sbi",
  "https://pineapple.com", "google.com", "HTTPS://WWW.GOOGLE.COM", "https://google.com.",
  "https://www.onlinesbi.sbi/login/account", "https://mail.google.co.in", "https://netbanking.hdfcbank.com",
  "https://1password.com", "https://www.irctc.co.in", "  https://paypal.me/x  ", "https://example.com:8443/x"];
const SCAMS = ["http://paypal-secure-login.xyz/verify", "https://sbi.kyc-update.top/login",
  "https://www.amazon.in.offers-today.xyz", "https://secure-login-hdfc.com", "http://192.168.4.20/bank",
  "http://[::1]/bank", "https://www.google.com@evil.example", "https://bit.ly/abc", "https://xn--pple-43d.com",
  "https://аpple.com", "http://3232235777/", "http://0x7f000001/", "http://127.1/", "http://0177.0.0.1/",
  "javascript:alert(1)", "DATA:text/html,<script>"];

test("links: real sites are clean, scams are flagged, junk is invalid", () => {
  for (const url of CLEAN) assert.deepStrictEqual(FS.checkLink(url), [], url);
  for (const url of SCAMS) assert.ok(FS.checkLink(url).length > 0, url);
  for (const url of ["", "   ", "http://[bad", "https://"]) {
    assert.deepStrictEqual(FS.checkLink(url), ["This doesn't look like a valid web address."], url);
  }
});

test("links: fuzzing never crashes", () => {
  const pieces = ["http://", "https://", "@", "[", "]", ":", "/", "xn--", ".", "-", "0x", "paypal", "%", "\\",
    "?", "#", "\x00", "а", "é", " ", "::1", ":99999", "😀"];
  let seed = 3;
  const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed % n; };
  for (let i = 0; i < 50000; i++) {
    let s = "";
    const len = rand(12);
    for (let j = 0; j < len; j++) s += rand(2) ? pieces[rand(pieces.length)] : String.fromCharCode(rand(0x3000));
    assert.ok(Array.isArray(FS.checkLink(s)));
    const r = FS.checkStrength(s);
    assert.ok(r.score >= 0 && r.score <= 4);
  }
});

test("checklist: scoring and priority order", () => {
  const n = FS.QUESTIONS.length;
  assert.deepStrictEqual(FS.scoreAnswers(new Array(n).fill(true)), { percent: 100, todo: [] });
  const none = FS.scoreAnswers(new Array(n).fill(false));
  assert.strictEqual(none.percent, 0);
  const weights = none.todo.map((t) => t[0]);
  assert.deepStrictEqual(weights, [...weights].sort((a, b) => b - a));
  assert.throws(() => FS.scoreAnswers([true]));
});

test("vault: round trip, wrong passphrase, unique salts", async () => {
  const blob = await FS.encryptBytes(enc("Aadhaar: 1234"), "pw");
  assert.ok(!Buffer.from(blob).includes("Aadhaar"));
  assert.strictEqual(dec(await FS.decryptBytes(blob, "pw")), "Aadhaar: 1234");
  await assert.rejects(FS.decryptBytes(blob, "wrong"), /Wrong passphrase/);
  const other = await FS.encryptBytes(enc("Aadhaar: 1234"), "pw");
  assert.notDeepStrictEqual(blob.slice(4, 20), other.slice(4, 20));
  assert.strictEqual((await FS.decryptBytes(await FS.encryptBytes(new Uint8Array(0), "pw"), "pw")).length, 0);
  const accented = await FS.encryptBytes(enc("x"), "café-mañana".normalize("NFC"));
  assert.strictEqual(dec(await FS.decryptBytes(accented, "café-mañana".normalize("NFD"))), "x");
});

test("vault: tampering, truncation and garbage are all rejected", async () => {
  const blob = await FS.encryptBytes(enc("s"), "pw");
  // Sample positions across the salt and every part of the token.
  const positions = [0, 3, 4, 10, 19, 20, 21, 25, 40, 60, 80, 100, blob.length - 20, blob.length - 1];
  for (const i of positions) {
    const damaged = blob.slice();
    damaged[i] ^= 1;
    await assert.rejects(FS.decryptBytes(damaged, "pw"), FS.VaultError, `byte ${i}`);
  }
  for (const length of [0, 4, 20, 21, 50, blob.length - 1]) {
    await assert.rejects(FS.decryptBytes(blob.slice(0, length), "pw"), FS.VaultError, `length ${length}`);
  }
  for (let i = 0; i < 20; i++) {
    const junk = new Uint8Array(20 + i * 7).map(() => Math.floor(Math.random() * 256));
    junk.set(enc("FSV1"));
    await assert.rejects(FS.decryptBytes(junk, "pw"), FS.VaultError);
  }
});

test("vault: files are interchangeable with the Python program", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fsv-"));
  const python = process.env.PYTHON || "python3";
  const run = (code) => execFileSync(python, ["-c", code], { cwd: path.join(__dirname, "..") }).toString();
  const secret = "PAN ABCDE1234F — बीमा पॉलिसी 😀\n".repeat(50);

  // JavaScript locks, Python unlocks.
  const fromJs = path.join(dir, "from-js.fsv");
  fs.writeFileSync(fromJs, await FS.encryptBytes(enc(secret), STRONG));
  const opened = run(`from family_shield import vault\nimport sys\nsys.stdout.buffer.write(vault.decrypt_bytes(open(${JSON.stringify(fromJs)},'rb').read(), ${JSON.stringify(STRONG)}))`);
  assert.strictEqual(opened, secret);

  // Python locks, JavaScript unlocks.
  const fromPy = path.join(dir, "from-py.fsv");
  run(`from family_shield import vault\nopen(${JSON.stringify(fromPy)},'wb').write(vault.encrypt_bytes(${JSON.stringify(secret)}.encode(), ${JSON.stringify(STRONG)}))`);
  assert.strictEqual(dec(await FS.decryptBytes(new Uint8Array(fs.readFileSync(fromPy)), STRONG)), secret);
  await assert.rejects(FS.decryptBytes(new Uint8Array(fs.readFileSync(fromPy)), "wrong"), FS.VaultError);
  fs.rmSync(dir, { recursive: true });
});
