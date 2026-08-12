import { SEED } from "./config.js";

const CLAIM_TIMEOUT_MS = 2500;

async function settings() {
  const stored = await chrome.storage.local.get(["port", "token", "enabled"]);
  return {
    port: stored.port ?? SEED.port,
    token: stored.token ?? SEED.token,
    enabled: stored.enabled ?? true,
  };
}

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(["port", "token", "enabled"]);
  const patch = {};
  if (stored.port === undefined) patch.port = SEED.port;
  if (stored.token === undefined) patch.token = SEED.token;
  if (stored.enabled === undefined) patch.enabled = true;
  if (Object.keys(patch).length) await chrome.storage.local.set(patch);
});

async function request(path, { port, token }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CLAIM_TIMEOUT_MS);
  try {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
      cache: "no-store",
    });
    if (!res.ok) return { error: `http ${res.status}` };
    return { data: await res.json() };
  } catch (err) {
    // The daemon simply not running is the common case — not worth surfacing.
    return { error: err.name === "AbortError" ? "timeout" : "unreachable" };
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    const cfg = await settings();

    if (msg?.type === "claim") {
      if (!cfg.enabled || !cfg.token) {
        sendResponse({});
        return;
      }
      const site = encodeURIComponent(String(msg.host || "").slice(0, 255));
      const { data, error } = await request(`/claim?site=${site}`, cfg);
      sendResponse(error ? {} : data || {});
      return;
    }

    if (msg?.type === "ping") {
      const { data, error } = await request("/health", cfg);
      sendResponse({ ok: !error, error, health: data });
      return;
    }

    sendResponse({});
  })();
  return true; // keep the message channel open for the async reply
});
