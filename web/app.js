/* Family Shield page behaviour: tabs, forms and buttons. The security logic
 * itself lives in shield-core.js. Kept in its own file (not inline in the
 * page) so the page's Content Security Policy can forbid inline scripts.
 */
(function () {
  "use strict";
  const FS = window.FamilyShield;
  const $ = (id) => document.getElementById(id);
  const inArtifact = !!(window.claude && window.claude.use);

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs || {})) {
      if (key === "text") node.textContent = value; else node.setAttribute(key, value);
    }
    for (const child of children || []) node.append(child);
    return node;
  }

  function verdict(kind, title, items) {
    const box = el("div", { class: "verdict " + kind }, [el("strong", { text: title })]);
    if (items && items.length) box.append(el("ul", {}, items.map((t) => el("li", { text: t }))));
    return box;
  }

  function show(target, node) { target.replaceChildren(node); }

  /* Tabs --------------------------------------------------------------- */
  const tabs = ["links", "passwords", "passphrases", "vault", "checkup"];
  function openTab(name) {
    if (!tabs.includes(name)) name = "links";
    for (const t of tabs) {
      $(t).hidden = t !== name;
      if (t === name) $("tab-" + t).setAttribute("aria-current", "page");
      else $("tab-" + t).removeAttribute("aria-current");
    }
    try { localStorage.setItem("fs-tab", name); } catch (storageBlocked) {}
  }
  document.querySelector("nav").addEventListener("click", (event) => {
    const link = event.target.closest("a");
    if (!link) return;
    event.preventDefault();
    const name = link.getAttribute("href").slice(1);
    openTab(name);
    try { history.replaceState(null, "", "#" + name); } catch (framed) {}
  });
  window.addEventListener("hashchange", () => openTab(location.hash.slice(1)));
  let startTab = location.hash.slice(1);
  if (!tabs.includes(startTab)) { try { startTab = localStorage.getItem("fs-tab") || "links"; } catch (e) { startTab = "links"; } }
  openTab(startTab);

  /* Scam links ----------------------------------------------------------- */
  function runLinkCheck() {
    const url = $("link-input").value;
    const warnings = FS.checkLink(url);
    if (!url.trim()) {
      show($("link-result"), el("p", { class: "muted", text: "Paste a link above." }));
    } else if (warnings.length === 0) {
      show($("link-result"), verdict("safe", "No obvious red flags.",
        ["Still, for banks and payments, use the official app instead of a link."]));
    } else if (warnings.length === 1 && /valid web address/.test(warnings[0])) {
      show($("link-result"), verdict("warn", warnings[0], ["Check you copied the whole link."]));
    } else {
      show($("link-result"), verdict("danger",
        `${warnings.length} red flag${warnings.length > 1 ? "s" : ""}. Do not open this link.`, warnings));
    }
  }
  $("link-form").addEventListener("submit", (event) => { event.preventDefault(); $("link-example-note").hidden = true; runLinkCheck(); });
  $("link-input").addEventListener("input", () => { $("link-example-note").hidden = true; });
  runLinkCheck();

  /* Passwords ---------------------------------------------------------- */
  let hashRun = 0;
  async function runPasswordCheck() {
    const pw = $("pw-input").value;
    $("breach-result").replaceChildren();
    $("breach-btn").disabled = !pw;
    if (!pw) {
      $("pw-meter").dataset.score = "-1";
      show($("pw-result"), el("p", { class: "muted", text: "Start typing to see a rating." }));
      $("pw-hash").textContent = "Hash appears here.";
      return;
    }
    const { score, label, problems } = FS.checkStrength(pw);
    $("pw-meter").dataset.score = String(score);
    const kind = score >= 3 ? "safe" : score === 2 ? "warn" : "danger";
    show($("pw-result"), verdict(kind, `${label} (${score}/4)`, problems));
    const run = ++hashRun;
    const hash = await FS.sha1Hex(pw);
    if (run !== hashRun) return;
    $("pw-hash").replaceChildren(el("span", { class: "sent", text: hash.slice(0, 5) }), hash.slice(5));
  }
  $("pw-input").addEventListener("input", runPasswordCheck);
  $("pw-show").addEventListener("change", () => { $("pw-input").type = $("pw-show").checked ? "text" : "password"; });
  $("breach-btn").addEventListener("click", async () => {
    const pw = $("pw-input").value;
    if (!pw) return;
    $("breach-btn").disabled = true;
    show($("breach-result"), el("p", { class: "muted", text: "Asking the breach service…" }));
    try {
      const count = await FS.timesSeenInBreaches(pw);
      if ($("pw-input").value !== pw) return;
      show($("breach-result"), count
        ? verdict("danger", `Seen ${count.toLocaleString()} times in data breaches.`,
            ["Attackers try leaked passwords first. Stop using it everywhere, starting with email and banking."])
        : verdict("safe", "Not found in known breaches.", ["That's good, but not a guarantee it's strong."]));
    } catch (error) {
      show($("breach-result"), verdict("warn", "Couldn't reach the breach service.", [
        inArtifact
          ? "This hosted preview blocks outside connections. Use the GitHub Pages version or the desktop program for this check."
          : "Check your internet connection and try again."]));
    } finally {
      $("breach-btn").disabled = !$("pw-input").value;
    }
  });

  /* Passphrases -------------------------------------------------------- */
  function makePhrases() {
    const list = $("phrases");
    list.replaceChildren();
    for (let i = 0; i < 5; i++) {
      const phrase = FS.generatePassphrase();
      const text = el("span", { class: "mono", text: phrase });
      const copy = el("button", { type: "button", class: "secondary", text: "Copy" });
      copy.addEventListener("click", () => {
        navigator.clipboard.writeText(phrase).then(() => { copy.textContent = "Copied"; }, () => {
          const range = document.createRange();
          range.selectNodeContents(text);
          const selection = getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          copy.textContent = "Selected - press Ctrl+C";
        });
      });
      list.append(el("div", { class: "phrase" }, [text, copy]));
    }
    $("phrase-bits").textContent = `About ${Math.round(FS.passphraseEntropyBits())} bits of entropy each.`;
  }
  $("more-phrases").addEventListener("click", makePhrases);
  makePhrases();

  /* Vault ---------------------------------------------------------------- */
  let downloadsPromise = null;
  async function offerFile(filename, bytes) {
    if (inArtifact) {
      downloadsPromise = downloadsPromise || window.claude.use("downloads");
      const downloads = await downloadsPromise;
      if (!downloads) throw new Error("Saving files isn't available in this view.");
      try {
        await downloads.save({ filename, data: new Blob([bytes]) });
      } catch (error) {
        if (error && error.code === "declined") throw new Error("Save cancelled.");
        if (error && error.code === "rejected_extension") {
          throw new Error("This hosted page can't save this file type. Use the GitHub Pages version or the desktop program.");
        }
        throw new Error((error && error.message) || "The file couldn't be saved.");
      }
      return;
    }
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    const link = el("a", { href: url, download: filename });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }

  function wireFileName(input, label) {
    input.addEventListener("change", () => { label.textContent = input.files[0] ? input.files[0].name : "No file chosen"; });
  }
  wireFileName($("lock-file"), $("lock-name"));
  wireFileName($("unlock-file"), $("unlock-name"));

  function progressFor(barId) {
    const bar = $(barId);
    bar.hidden = false;
    bar.firstElementChild.style.width = "0";
    return (fraction) => { bar.firstElementChild.style.width = Math.round(fraction * 100) + "%"; };
  }

  async function busy(buttonId, work) {
    const button = $(buttonId);
    const text = button.textContent;
    button.disabled = true;
    button.textContent = "Working…";
    try { await work(); } finally { button.disabled = false; button.textContent = text; }
  }

  $("lock-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const out = $("lock-result");
    const file = $("lock-file").files[0];
    const pass = $("lock-pass").value;
    if (!file) return show(out, verdict("warn", "Choose a file to lock first."));
    if (file.size > FS.MAX_FILE_BYTES) return show(out, verdict("warn", FS.TOO_BIG));
    if (pass !== $("lock-pass2").value) return show(out, verdict("warn", "The two passphrases don't match.", ["Nothing was changed."]));
    if (FS.checkStrength(pass).score < 3) {
      return show(out, verdict("danger", "That passphrase is too weak for protecting documents.",
        ["Use the Passphrases tab for a strong one you can remember."]));
    }
    out.replaceChildren();
    busy("lock-btn", async () => {
      try {
        const data = new Uint8Array(await file.arrayBuffer());
        const locked = await FS.encryptBytes(data, pass, progressFor("lock-progress"));
        // The hosted preview only saves certain file types, so ".fsv" rides as ".fsv.txt" there.
        const name = file.name + (inArtifact ? ".fsv.txt" : ".fsv");
        await offerFile(name, locked);
        show(out, verdict("safe", `Locked copy saved as ${name}.`, [
          "Unlock it once to check it works, then delete the original.",
          "Keep the passphrase written down somewhere safe."]));
      } catch (error) {
        show(out, verdict("danger", error.message || "Locking failed."));
      }
    });
  });

  $("unlock-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const out = $("unlock-result");
    const file = $("unlock-file").files[0];
    const pass = $("unlock-pass").value;
    if (!file) return show(out, verdict("warn", "Choose a locked .fsv file first."));
    if (file.size > FS.MAX_LOCKED_BYTES) return show(out, verdict("warn", FS.TOO_BIG));
    out.replaceChildren();
    busy("unlock-btn", async () => {
      try {
        const blob = new Uint8Array(await file.arrayBuffer());
        const data = await FS.decryptBytes(blob, pass, progressFor("unlock-progress"));
        if (data.length === 0) return show(out, verdict("safe", "Unlocked. The original file was empty, so there is nothing to save."));
        let name = file.name.replace(/\.fsv(\.txt)?$/i, "");
        if (!name || name === file.name) name = "unlocked-" + file.name;
        await offerFile(name, data);
        show(out, verdict("safe", `Unlocked and saved as ${name}.`));
      } catch (error) {
        show(out, verdict("danger", error.message || "Unlocking failed."));
      }
    });
  });

  /* Check-up ----------------------------------------------------------- */
  const answers = new Array(FS.QUESTIONS.length).fill(null);
  const PRIORITY = { 3: "Critical", 2: "Important", 1: "Good idea" };
  FS.QUESTIONS.forEach(([question, weight], i) => {
    const yes = el("button", { type: "button", class: "yes", "aria-pressed": "false", text: "Yes" });
    const no = el("button", { type: "button", class: "no", "aria-pressed": "false", text: "No" });
    const pick = (value) => {
      answers[i] = value;
      yes.setAttribute("aria-pressed", String(value === true));
      no.setAttribute("aria-pressed", String(value === false));
      updateScore();
    };
    yes.addEventListener("click", () => pick(true));
    no.addEventListener("click", () => pick(false));
    $("questions").append(el("div", { class: "question" }, [
      el("p", {}, [el("span", { class: "weight w" + weight, text: PRIORITY[weight] }), el("br"), question]),
      el("div", { class: "yn", role: "group", "aria-label": question }, [yes, no]),
    ]));
  });
  function updateScore() {
    const answered = answers.filter((a) => a !== null).length;
    if (answered < answers.length) {
      $("score").textContent = "–";
      $("score-note").textContent = `${answered} of ${answers.length} answered.`;
      $("todo").replaceChildren();
      return;
    }
    const { percent, todo } = FS.scoreAnswers(answers);
    $("score").textContent = percent + "%";
    $("score-note").textContent = todo.length ? "Your to-do list, most important first:" : "Excellent. Re-check every few months.";
    $("todo").replaceChildren(el("ol", { class: "todo" }, todo.map(([weight, advice]) =>
      el("li", {}, [el("span", { class: "weight w" + weight, text: PRIORITY[weight] + " " }), advice]))));
  }
})();
