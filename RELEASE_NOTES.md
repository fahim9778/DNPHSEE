# DNPHSEE v1.3.3 — First public release

An independent, customizable Gmail inbox firewall for busy institutional mailboxes.

### Highlights

- **One-click conversation block:** Open any message, use the Gmail sidebar, preview in DRY_RUN or archive the thread in LIVE.
- **Future-reply suppression:** Remember exact thread and email-reference identifiers; later replies can be suppressed even when classified KEEP, while protected duties remain safe.
- **Free automation:** One-minute Apps Script scanner and optional Workspace Studio labels; no paid Gemini Developer API.
- **Safety first:** No permanent deletion. Admission-test, invigilation/proctoring, student correspondence and important institutional tasks are prioritized; ambiguous emails stay in view.
- **Cleaner Gmail:** Compact nested `ZZ` labels, red `ZZ/AF_N` noise chip, and an included custom icon.

### Install

See [INSTALL.md](INSTALL.md). Start with `setupFirewall()` in DRY_RUN, optionally configure Studio, install the Gmail test add-on, and review before running `goLive()`.

### Notes

The included Node tests use mocked Google services; actual Gmail add-on installation requires Google Workspace permissions. Back up your old project and pause suppression before upgrading an existing installation. Never commit real email or your private ledger.