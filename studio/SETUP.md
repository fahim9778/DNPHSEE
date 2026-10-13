# Optional Workspace Studio setup

Use your own Workspace account with Google Workspace Studio access. These steps are optional—DNPHSEE does not require the paid Gemini Developer API.

1. Create a flow named **DNPHSEE Inbox Triage**.
2. Starter: **When I get an email** → all incoming mail, including replies.
3. Add **Decide**; paste [`DECIDE_PROMPT.txt`](DECIDE_PROMPT.txt). At the end of the prompt, insert Studio's actual variable chips for **Sender email address**, **Email subject**, and **Email body** (and recipients if available). Don't leave placeholder text in place of chips.
4. In **Check if Step 2 Decision is true**, choose **Add labels with Gemini**, select Step 1 **Email ID**, turn **AI-powered labels OFF**, and select **only `ZZ/AF_N`**.
5. Add a separate **Check if Step 2 Decision is false** with the same Gmail label action, selecting **only `ZZ/AF_K`**. Ensure neither branch selects the other label.
6. **Do not add Archive or Delete actions** in Studio. Script decisions and final safety checks must control archival.
7. Test one clearly nonessential invitation and one important student/duty email. Only after the decisions and labels are correct, turn on the flow.

The `ZZ` labels are created by `setupFirewall()` in Apps Script. If labels were renamed, reselect their currently nested versions in Studio; cached selections can point to legacy names. Keep the Script in DRY_RUN during initial testing.
