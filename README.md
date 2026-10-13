# DNPHSEE

**Less inbox noise. More mail that actually matters.**

DNPHSEE is a lightweight, self-hosted Gmail inbox firewall for people who receive a lot of optional institutional broadcasts, announcements, and endless reply-all chains. It runs with **Google Apps Script** and, optionally, **Google Workspace Studio**. No paid Gemini Developer API, external server, or browser extension is required.

![DNPHSEE icon](assets/AcademicFirewall_128.png)

> **Public preview · v1.3.3.** This tool can alter your mailbox. Install in **DRY_RUN**, review decisions, and only then opt into LIVE archiving. No classification method is perfect.

## What it does

- **Triage incoming mail** with an optional Google Workspace Studio `Decide` flow and free, conservative Apps Script rules.
- **Archive—not delete—eligible nuisance messages**, such as broadcast congratulations, voluntary performances, cultural events, social invitations, and unnecessary reply-all messages.
- **Block an entire conversation** using a contextual Gmail sidebar button; opening any reply can select its parent thread.
- **Remember identifiers** in a private Google Sheet to suppress recognizable later replies, even if Gmail assigns a new thread after an earlier message is removed.
- **Protect professional duties:** admissions-test invitations, invigilation/proctoring opportunities, important examinations, student correspondence, HR and required institutional notices.
- **Allow manual overrides**, keep an Audit history, and maintain pending/review queues when a message cannot be classified safely.
- Use short labels grouped under **`ZZ`** (`ZZ/AF_K`, `ZZ/AF_N`, etc.). The `ZZ/AF_N` noise chip defaults to **red with white text**.

**Important:** A recognized reply may still briefly enter the inbox before a scheduled scan. Missing/altered reply headers and messages unreadable from MIME content may escape suppression; protected or uncertain messages are generally retained for safety. Do not use it to guarantee delivery of critical messages.

## Quick start

1. Open [Google Apps Script](https://script.google.com/) using the mailbox you want to manage. Create a project and paste **`Code.gs`** and **`GmailAddon.gs`** as separate script files.
2. Show the manifest in **Project Settings → Show `appsscript.json`**, then replace it with the supplied manifest. Authorize the scopes, and run `setupFirewall()` once. It creates the labels, private ledger, and one-minute trigger in **DRY_RUN**.
3. If Workspace Studio is available, follow [the Studio guide](studio/SETUP.md) to classify new messages into `ZZ/AF_N` (noise) and `ZZ/AF_K` (keep).
4. Install the sidebar from **Deploy → Test deployments → Install**. Refresh Gmail and open an individual message to preview **Block this conversation**.
5. Review `ZZ/AF_R` (review candidates) and the ledger's Audit tab. When confident, run `goLive()` in Apps Script. Use `pauseSuppression()` to go back to DRY_RUN any time.

Full instructions: **[INSTALL.md](INSTALL.md)**.

## Key controls

| Apps Script function | Purpose |
| --- | --- |
| `setupFirewall()` | First-time setup / reinitialize trigger while preserving existing ledger |
| `statusFirewall()` | Show mode, labels and private ledger URL in execution log |
| `setNoiseLabelRed()` | Apply the default red color to `ZZ/AF_N` without changing other labels |
| `scanMailbox()` | Process candidates immediately instead of waiting for the timer |
| `pauseSuppression()` | Stop automatic archiving (DRY_RUN) |
| `goLive()` | Enable automatic archiving and remembered conversation blocking |
| `testProtectedDutyRules()` | Test admission-test and invigilation protection patterns |
| `testOneClickSafetyV130()` | Test the Gmail add-on's subject safety rules |

## Privacy and data handling

The script uses the Gmail API, GmailApp, SpreadsheetApp, and time-driven triggers within your Google account. The **Private Ledger is never part of this public repository**. It contains message/thread identifiers, subjects, senders, and decisions. Keep that spreadsheet private. The Apps Script code contains no paid Gemini API calls or email forwarding behavior. The optional Workspace Studio flow processes message text through your Workspace environment; confirm it is allowed by your organization.

Permissions are broad because the tool must read, label, and archive mail. **Review the manifest before consenting.** Archiving is reversible via Gmail All Mail, but remember that stored identifiers may archive future replies until unblocked. The add-on refuses large, unreadable or protected conversations. See [SECURITY.md](SECURITY.md).

## Customize

- Edit `AF.importantSubject`, `AF.trustedSenders`, and `AF.trustedRecipients` in `Code.gs` for your department and verified critical senders. **Do not globally allow or block an entire institutional email domain.**
- The free rules recognize broad broadcast aliases (e.g., `all@...`, `faculty@...`) without hardcoding an institution.
- Update the [Studio classification prompt](studio/DECIDE_PROMPT.txt) for your role and language while keeping the protected-duty rule.
- The Gmail icon is shipped in [`assets/`](assets/). The manifest `logoUrl` points to this repository's public raw icon once the repository is published.

## Test locally

Requires Node.js. Runs simulations only; it does **not** connect to Gmail or any other Google API.

```bash
node tests/test_firewall.js
```

**74 simulated checks** passed in the release preparation environment. This is not a substitute for live testing with your own account and actual Workspace permissions.

## Contributing

Contributions and reports of over-filtering are welcome, especially improvements to safer opt-in behavior, reply ancestry handling, and multilingual event detection. Never attach real student correspondence, private mail, OAuth credentials, or an export of your Private Ledger to an issue.

Licensed under the [MIT License](LICENSE). This is a community project, not an official institutional or Google product.