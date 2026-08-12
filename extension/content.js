(() => {
  "use strict";

  const POLL_MS = 2000;
  const REFILL_COOLDOWN_MS = 60000;
  const IS_TOP = window.top === window;

  // Words that mark a field as a passcode box...
  const OTP_HINT =
    /(?:^|[^a-z])(otp|totp|mfa|2fa|one[-_\s]?time|onetime|verification|verify|confirmation|security[-_\s]?code|auth(?:entication)?[-_\s]?code|passcode|sms[-_\s]?code|challenge)(?:[^a-z]|$)/i;

  // ...and words that mean it is something else that merely sounds similar.
  const NEGATIVE_HINT =
    /(search|query|e-?mail|phone|address|street|card[-_\s]?number|cvv|cvc|expir|zip|postal|coupon|promo|discount|gift[-_\s]?card|username|user[-_\s]?name|answer|question)/i;

  let lastFillAt = 0;

  // ---------------------------------------------------------------- detection

  const isVisible = (el) => {
    if (!el.isConnected || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none" && s.opacity !== "0";
  };

  function describe(el) {
    const bits = [
      el.id,
      el.name,
      el.placeholder,
      el.getAttribute("aria-label"),
      el.getAttribute("autocomplete"),
      el.getAttribute("data-testid"),
    ];
    if (el.labels) for (const l of el.labels) bits.push(l.textContent);
    const describedBy = el.getAttribute("aria-describedby");
    if (describedBy) {
      const node = document.getElementById(describedBy);
      if (node) bits.push(node.textContent);
    }
    return bits.filter(Boolean).join(" ").slice(0, 400);
  }

  function candidateInputs() {
    const allowed = new Set(["text", "tel", "number", "password", ""]);
    return Array.from(document.querySelectorAll("input")).filter(
      (el) => allowed.has((el.type || "text").toLowerCase()) && isVisible(el)
    );
  }

  function findTarget() {
    const inputs = candidateInputs();

    // Segmented widgets: a row of single-character boxes.
    const byParent = new Map();
    for (const el of inputs) {
      if (el.maxLength !== 1) continue;
      const parent = el.parentElement;
      if (!parent) continue;
      if (!byParent.has(parent)) byParent.set(parent, []);
      byParent.get(parent).push(el);
    }
    for (const group of byParent.values()) {
      if (group.length >= 4 && group.length <= 8) return { kind: "segmented", els: group };
    }

    // The standard attribute — highest confidence, no guessing.
    const explicit = inputs.find((el) =>
      (el.getAttribute("autocomplete") || "").split(/\s+/).includes("one-time-code")
    );
    if (explicit) return { kind: "single", el: explicit };

    // Fall back to reading the field's own labelling.
    const guessed = inputs.find((el) => {
      const text = describe(el);
      return OTP_HINT.test(text) && !NEGATIVE_HINT.test(text);
    });
    return guessed ? { kind: "single", el: guessed } : null;
  }

  const isEmpty = (target) =>
    target.kind === "single"
      ? target.el.value === ""
      : target.els.every((el) => el.value === "");

  // ------------------------------------------------------------------ filling

  // React (and friends) track input values on the node, so assigning .value
  // directly is swallowed. Going through the prototype's setter defeats the
  // value tracker and makes the subsequent input event count as a real change.
  function setNativeValue(el, value) {
    const proto = Object.getPrototypeOf(el);
    const desc =
      Object.getOwnPropertyDescriptor(proto, "value") ||
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
  }

  const fire = (el, type) => el.dispatchEvent(new Event(type, { bubbles: true }));
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function fillSingle(el, code) {
    el.focus();
    setNativeValue(el, code);
    fire(el, "input");
    fire(el, "change");
  }

  async function fillSegmented(els, code) {
    const chars = String(code).split("");
    for (let i = 0; i < els.length && i < chars.length; i++) {
      const el = els[i];
      el.focus();
      el.dispatchEvent(new KeyboardEvent("keydown", { key: chars[i], bubbles: true }));
      setNativeValue(el, chars[i]);
      fire(el, "input");
      el.dispatchEvent(new KeyboardEvent("keyup", { key: chars[i], bubbles: true }));
      fire(el, "change");
      await sleep(30);
    }
  }

  function highlight(el) {
    const previous = el.style.boxShadow;
    el.style.boxShadow = "0 0 0 3px rgba(56,189,248,.9)";
    setTimeout(() => {
      el.style.boxShadow = previous;
    }, 1600);
  }

  // -------------------------------------------------------------------- toast

  function toast(code, sender) {
    // In a small iframe the banner would be clipped; the Notification Center
    // banner from the daemon already covers that case.
    if (window.innerWidth < 240 || window.innerHeight < 120) return;

    const host = document.createElement("div");
    // `all:initial` must come FIRST — it is a shorthand for every property, so
    // trailing it would reset the positioning declared before it.
    host.style.cssText =
      "all:initial;position:fixed;top:16px;right:16px;z-index:2147483647;";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        .card{font:13px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif;
          background:rgba(28,28,30,.96);color:#fff;padding:10px 14px;border-radius:12px;
          box-shadow:0 8px 28px rgba(0,0,0,.35);display:flex;gap:10px;align-items:center;
          animation:in .18s ease-out;max-width:320px}
        .code{font-weight:650;letter-spacing:.09em;font-variant-numeric:tabular-nums}
        .muted{opacity:.7}
        @keyframes in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
      </style>
      <div class="card">
        <span>💬</span>
        <div>
          <div><span class="code"></span> <span class="muted from"></span></div>
          <div class="muted">Filled — not submitted</div>
        </div>
      </div>`;
    root.querySelector(".code").textContent = code;
    root.querySelector(".from").textContent = sender ? `from ${sender}` : "";
    (document.body || document.documentElement).appendChild(host);
    setTimeout(() => host.remove(), 6000);
  }

  // --------------------------------------------------------------------- loop

  function tabActive() {
    if (document.visibilityState !== "visible") return false;
    // hasFocus() is false for a subframe the user has not clicked into, which
    // would block legitimate fills in embedded checkout/2FA iframes.
    return IS_TOP ? document.hasFocus() : true;
  }

  async function tick() {
    if (!tabActive()) return;
    if (Date.now() - lastFillAt < REFILL_COOLDOWN_MS) return;

    const target = findTarget();
    if (!target || !isEmpty(target)) return;

    let reply;
    try {
      reply = await chrome.runtime.sendMessage({ type: "claim", host: location.hostname });
    } catch {
      return; // extension reloaded or context invalidated
    }
    if (!reply || !reply.code) return;

    // The page may have changed while we were waiting on the daemon.
    const fresh = findTarget();
    if (!fresh || !isEmpty(fresh)) return;

    lastFillAt = Date.now();
    if (fresh.kind === "single") {
      fillSingle(fresh.el, reply.code);
      highlight(fresh.el);
    } else {
      await fillSegmented(fresh.els, reply.code);
      highlight(fresh.els[fresh.els.length - 1]);
    }
    toast(reply.code, reply.sender);
  }

  setInterval(() => {
    tick().catch(() => {});
  }, POLL_MS);
})();
