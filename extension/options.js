const $ = (id) => document.getElementById(id);
const status = $("status");

function say(text, cls = "") {
  status.textContent = text;
  status.className = cls;
}

(async function load() {
  const cfg = await chrome.storage.local.get(["port", "token", "enabled"]);
  $("port").value = cfg.port ?? 8787;
  $("token").value = cfg.token ?? "";
  $("enabled").checked = cfg.enabled ?? true;
})();

$("save").addEventListener("click", async () => {
  const port = Number($("port").value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    say("Port must be between 1 and 65535.", "bad");
    return;
  }
  await chrome.storage.local.set({
    port,
    token: $("token").value.trim(),
    enabled: $("enabled").checked,
  });
  say("Saved.", "ok");
});

$("test").addEventListener("click", async () => {
  say("Checking…");
  const res = await chrome.runtime.sendMessage({ type: "ping" });
  if (res?.ok) {
    const health = res.health || {};
    if (health.db_access === false) {
      say(
        "Daemon is running but cannot read Messages. Grant Full Disk Access to " +
          "“OTP Autofill.app” in System Settings → Privacy & Security.",
        "bad"
      );
      return;
    }
    say(`Daemon reachable (v${health.version}), ${health.pending ?? 0} code(s) waiting.`, "ok");
  } else {
    say(`Cannot reach the daemon (${res?.error || "unknown"}). Is it running?`, "bad");
  }
});
