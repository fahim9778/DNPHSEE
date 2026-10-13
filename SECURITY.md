# Security and privacy

DNPHSEE is an inbox automation tool, not a spam-detection security product. It is distributed as source code for review and self-deployment. It has not undergone an independent security audit or a production reliability certification.

## Access and data

- The script requests Gmail modify access to inspect messages and archive/label them. It also uses Google Sheets to store **private** ledger identifiers, message subjects, senders, and decision logs.
- The Gmail add-on uses the selected message's access token only inside the execution, and should never print or store it.
- The repository contains no real mailbox export, authorization tokens, API keys, or private ledgers. Never add those to an issue, commit, or release asset.
- The optional Workspace Studio flow uses your organization's Google Workspace processing. Do not enable it without permission for the information in your mailbox.
- There is no outbound email forwarding or paid external Gemini API call in the code distributed here.

## Operational safety

- Default to DRY_RUN, review the `ZZ/AF_R` candidates, and only then use LIVE.
- Admission-test/invigilation wording and relevant duty replies are protected by pre-archive checks, but no text-only classifier can detect all context, including attachments and pictures.
- Unknown, ambiguous and unreadable content should remain for review. If you see inappropriate classifications, stop archival immediately with `pauseSuppression()`.
- Never assume Gmail's Importance flag is a reliable indication of mandatory work.
- The remembered-block database can cause later replies in a recognized lineage to be archived. Restoring a message from All Mail does not remove a remembered block. Use `unblockThreadByLedgerId` when reversing a block, and inspect related entries in the private ledger.

## Reporting

Please report reproducible issues using **fictional examples** and redacted logs. Do not include names, actual email addresses, message IDs from private correspondence, student information, or copies of personal email. If an urgent problem may archive important mail, first switch to DRY_RUN.