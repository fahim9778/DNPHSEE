# Installing DNPHSEE

## Before you begin

- A Gmail or eligible Google Workspace mailbox in which you can authorize Apps Script.
- Permission to read and organize that mailbox, including approval from your Workspace administrator where applicable.
- Google Workspace Studio is **optional**; the free local rules and the Gmail add-on work without an external AI key.

**Start in DRY_RUN.** The example project has powerful Gmail permissions and should not be tested first on mission-critical correspondence.

## 1. Set up Apps Script

1. Create a new project at <https://script.google.com/>.
2. Replace the default `Code.gs` with the contents of the repository's `Code.gs`.
3. Click **+ → Script** and name it `GmailAddon`; paste `GmailAddon.gs`.
4. In **Project Settings**, show the `appsscript.json` manifest and replace it with this repository's `appsscript.json`. Do not remove OAuth scopes.
5. Save all files and run **`setupFirewall`** from the function dropdown. Review the permissions requested. It creates a private spreadsheet (`BlockedKeys`, `AllowedKeys`, `Audit`, `Pending`), Gmail labels under `ZZ`, and a one-minute scheduled `scanMailbox` trigger.
6. Run **`statusFirewall`**. Verify `mode: DRY_RUN` and note the ledger URL printed in the execution log.

The manifest enables the advanced Gmail service. If your editor reports that `Gmail` is unavailable, confirm the Gmail API under Apps Script **Services** and that your administrator permits it.

**Label appearance:** `ZZ/AF_N` receives a red background and white text automatically. If upgrading an existing installation and the color does not change, run `setNoiseLabelRed()` once. This changes appearance only, not classification or archive behavior.

## 2. Optional Google Workspace Studio classification

Follow [studio/SETUP.md](studio/SETUP.md). The studio flow applies labels **only**; do not put an Archive action inside the flow. The script applies protective checks before archival.

If Studio isn't available, leave it disconnected. Local rules can still flag obvious broadcasts, but some messages will remain pending.

## 3. Install the Gmail sidebar add-on

In Apps Script: **Deploy → Test deployments → Install**. If your account is managed, the administrator may restrict installing private test add-ons. Refresh Gmail, open an individual message, and click the DNPHSEE icon in the right sidebar.

In DRY_RUN, use **Preview block (DRY_RUN)**. The message toast should report a count such as `4 message(s) eligible. No changes made.`

If no context appears, expand a message in the conversation and reopen the sidebar. The add-on gets the message ID from Gmail's event, not from an opaque `FMfcgz...` URL.

## 4. Verify the dry-run decisions

1. Send yourself a harmless optional social-event invitation and a separate harmless required-duty example, or select existing low-risk messages for a Studio test run.
2. Run `scanMailbox` in Apps Script.
3. In Gmail, review `ZZ/AF_R` (the candidates that **would** be archived), `ZZ/AF_N` (Studio noise), and `ZZ/AF_RN` (local rule noise).
4. Check the private ledger's `Audit` tab for `WOULD_ARCHIVE`. Messages remain in Inbox while DRY_RUN is active.
5. Test `testProtectedDutyRules()` and `testOneClickSafetyV130()`.

Do not enable LIVE before reviewing potential false positives. **Private Ledger identifiers and student subjects should never be uploaded to a public GitHub repository.**

## 5. Turn on or pause

- **`goLive()`** enables automatic archival of eligible inbox messages and recording persistent conversation identifiers in `BlockedKeys`.
- **`pauseSuppression()`** disables archival by this script, leaving Studio label classification enabled.
- **`statusFirewall()`** confirms the current state.

Turning LIVE on can process already-flagged inbox messages. Archiving is not deletion; find them later in Gmail's **All Mail**. Pausing does not restore archived messages or erase stored blocks. To remove a remembered block, see the helper `unblockThreadByLedgerId(threadId)` in `Code.gs` and restore the message to Inbox manually if needed.

## Migrating an existing private installation

Back up `Code.gs`, `GmailAddon.gs`, and the manifest before replacing them. Run `pauseSuppression()` first, paste the new source files, and leave the existing private spreadsheet and labels intact. `setupFirewall()` can refresh the trigger without replacing an existing ledger; the initial mode remains DRY_RUN unless the project was already LIVE, so use `pauseSuppression()` explicitly.

### Runtime and limitations

- Background checks are scheduled approximately **once per minute**, subject to Apps Script quotas and delays—not instantaneous delivery-time filtering.
- Each user authorizes their own project and keeps their own private ledger. There is no shared inbox database.
- Gmail notifications may occur before an eligible message is archived.
- Workspace Studio classification isn't guaranteed for older or missed messages. The local fallback is conservative and keeps uncertain messages.
- Some relevant information may exist only in an image or attachment; the text-only safety guard may not recognize it. Review the configuration and use a conservative DRY_RUN period.