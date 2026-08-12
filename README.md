# Messages OTP Autofill

SMS verification codes that arrive in the macOS **Messages** app get filled into
the verification field in **Chrome**, the way iPhone does it — and copied to the
clipboard as a fallback for everything else.

macOS already does this natively in Safari via Continuity. Chrome is the gap;
this closes it.

**It fills the field. It never submits the form.**

---

## How it works

```
Messages.app ──> chat.db ──> watcher daemon ──┬──> clipboard + notification
                             (LaunchAgent)    │
                                              └──> 127.0.0.1:8787  <── Chrome extension
                                                   (bearer token)       (fills the field)
```

1. A **LaunchAgent daemon** polls `~/Library/Messages/chat.db` every 1.5s for new
   inbound messages and extracts the passcode.
2. Every code is **copied to the clipboard** and raises a Notification Center
   banner. This path always works — Arc, Firefox, native apps, anywhere.
3. The code is also parked on a **loopback-only HTTP endpoint**. When the Chrome
   extension sees a one-time-code field on the focused page, it claims the code
   and fills it.

Nothing leaves the machine. There is no cloud component.

---

## Install

```bash
~/Projects/otp-autofill/setup.sh
```

That generates a token, builds the app bundle, installs the LaunchAgent and
starts it. Then two manual steps that only you can do:

**A. Grant Full Disk Access** (required to read Messages)

System Settings → Privacy & Security → Full Disk Access → **+** →
`~/Applications/OTP Autofill.app`

Then pick it up without a reboot:

```bash
launchctl kickstart -k gui/$(id -u)/com.kyra.otp-autofill
```

**B. Load the Chrome extension**

`chrome://extensions` → enable **Developer mode** → **Load unpacked** →
`~/Projects/otp-autofill/extension`

The token is baked into `extension/config.js` by `setup.sh`, so there is nothing
to copy by hand.

Verify:

```bash
~/Projects/otp-autofill/daemon/otp_watcher.py --check
```

---

## Why the app bundle

Reading `chat.db` requires Full Disk Access. The obvious install would grant FDA
to your Python binary — but that hands full-disk rights to *every* script you
ever run with that interpreter.

Instead `setup.sh` builds `~/Applications/OTP Autofill.app` around a **private
copy** of the interpreter (34 KB, via `venv --copies`), ad-hoc signed with its
own bundle identity. The grant applies to this tool alone.

---

## Security posture

- The HTTP server binds **127.0.0.1 only** — never a routable interface.
- Every request needs a **bearer token** (32 bytes, `secrets.token_urlsafe`),
  stored `0600` in `~/.config/otp-autofill/config.json`.
- Codes are **single-use** and **expire after 5 minutes**.
- The endpoint returns only the code digits and a sender label — **never message
  text**. The daemon never exposes a way to read your messages.
- The extension only claims a code when the tab is **visible and focused** and an
  **empty** one-time-code field is actually present.
- Codes carrying the origin-bound `@example.com #123456` convention are only
  released to a matching hostname.
- Every claim is logged with the site that received it — see
  `~/Library/Logs/otp-autofill.log`.
- The extension runs a content script on all pages (unavoidable — the field can
  be anywhere). It reads the DOM to find passcode fields and sends **only the
  hostname** to the local daemon. It has no other network permission: the
  manifest allows `http://127.0.0.1/*` and nothing else.

**It fills but never submits**, so you always see the code and the page before
anything is sent.

---

## Code detection

The extractor was tuned against ~61,000 real inbound messages, not guesses.

A message must read as a passcode message before any digits are pulled out of it,
which kills most false positives on its own. On top of that:

- Meeting invites (Zoom/Teams/Meet "Passcode: …") are excluded — they match the
  wording but are not 2FA codes.
- Group threads are excluded. Codes do not arrive in group chats, but door codes
  and wifi passwords do. This was the only heuristic needed to catch every real
  false positive in the archive (a holiday-rental entry code, a front-door code).
- The origin-bound `@domain #code` form requires a digit, so marketing posts of
  the shape `@somevenue.example #somehashtag` no longer parse as a code.

A "have you replied to this sender" filter was tried and **removed**: it dropped
genuine codes from two banks, a telecom and a large retailer, because two-way SMS
with a service shortcode is completely normal.

Run the regression suite:

```bash
~/Projects/otp-autofill/daemon/otp_watcher.py --selftest
```

---

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `--check` says db access ✗ | Full Disk Access not granted to `OTP Autofill.app`, or granted but not restarted — `launchctl kickstart -k gui/$(id -u)/com.kyra.otp-autofill` |
| Extension "Test connection" says unreachable | Daemon not running: `launchctl print gui/$(id -u)/com.kyra.otp-autofill` |
| Code copied to clipboard but not filled | The page's field did not match. Check the log for `claimed … -> <site>`; if the claim happened, detection worked and the fill did not — file the field's HTML |
| Nothing after a Python upgrade | Re-run `setup.sh` — the bundled interpreter points at the Homebrew framework |

Logs: `~/Library/Logs/otp-autofill.log`

---

## Known limitations

- If a passcode field is open and focused when an **unrelated** code arrives,
  that code gets filled there. The toast names the sender so you can see the
  mismatch before submitting, and the clipboard still holds it. Sites that use
  the origin-bound `@domain #code` convention are immune.
- Chrome only. Safari needs none of this; Arc/Firefox get the clipboard path.
- Segmented inputs are detected as 4–8 single-character boxes sharing a parent.
  Exotic layouts may not match.

## Uninstall

```bash
~/Projects/otp-autofill/uninstall.sh
```
