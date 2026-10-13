/**
 * DNPHSEE v1.3.3 — Gmail one-click thread blocker (thread membership hotfix).
 * Install as an unpublished Google Workspace add-on via Deploy > Test deployments.
 * Requires the SAME Apps Script project as Code.gs, not a separate project.
 * The browser's opaque FMfcgz URL is never parsed: Gmail supplies IDs in e.gmail.
 * No Gemini Developer API, billing, external calls, deletion, or sending mail.
 */
const AF130 = Object.freeze({maxThreadMessages: 80, maxBodyChars: 64000});

/** Contextual card appears in Gmail's right side panel for the opened email. */
function af130OpenMessage(e) {
  try {
    const messageId = af130CurrentMessageId_(e);
    const raw = Gmail.Users.Messages.get('me', messageId, {
      format:'metadata', metadataHeaders:['Subject','From']
    });
    const subject = af130Header_(raw, 'subject') || '(No subject)';
    const sender = af130Header_(raw, 'from') || '(Unknown sender)';
    const mode = af130Mode_();
    const buttonTitle = mode === 'LIVE'
      ? 'Block this conversation'
      : 'Preview block (DRY_RUN)';
    const action = CardService.newAction()
      .setFunctionName('af130BlockCurrentThread')
      .setParameters({expectedMessageId: messageId, expectedThreadId: raw.threadId});
    const section = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        '<b>Mode:</b> ' + af130Esc_(mode) +
        (mode !== 'LIVE' ? ' — nothing will be archived or remembered.' :
        ' — eligible messages will be archived and their identifiers remembered.')))
      .addWidget(CardService.newDecoratedText().setTopLabel('Selected conversation')
        .setText(af130Esc_(subject.slice(0, 180))))
      .addWidget(CardService.newDecoratedText().setTopLabel('Sender')
        .setText(af130Esc_(sender.slice(0, 150))))
      .addWidget(CardService.newTextButton()
        .setText(buttonTitle)
        .setOnClickAction(action));
    return [CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('DNPHSEE')
        .setSubtitle('Block selected conversation'))
      .addSection(section).build()];
  } catch (err) {
    return [CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('DNPHSEE'))
      .addSection(CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(
          'Cannot inspect this email: ' + af130Esc_(safeError_(err)))))
      .build()];
  }
}

/** Single action initiated from Gmail's contextual card. */
function af130BlockCurrentThread(e) {
  let message = 'No changes made.';
  try {
    const messageId = af130CurrentMessageId_(e);
    const supplied = String((e && e.parameters && e.parameters.expectedMessageId) || '');
    if (supplied && messageId !== supplied) {
      throw Error('The selected email changed. Reopen the add-on for the current email.');
    }
    const expectedThread = String((e && e.parameters && e.parameters.expectedThreadId) || '');
    const result = af130BlockByMessageId_(messageId, expectedThread);
    message = result.mode === 'DRY_RUN'
      ? 'DRY_RUN: ' + result.inboxCount + ' message(s) eligible. No changes made.'
      : result.archived + ' message(s) archived; conversation remembered for future replies.';
  } catch (err) {
    message = 'Not blocked: ' + safeError_(err);
    console.error('One-click block refused: ' + safeError_(err));
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(message.slice(0, 250)))
    .setStateChanged(true).build();
}

/**
 * Read the selected Gmail message context. The event ID is opaque: do not
 * assume it has a particular length or character set. Apps Script also
 * historically used messageMetadata for some Gmail add-on events.
 *
 * Never log e or e.gmail in full: the event can contain an access token.
 */
function af130CurrentMessageId_(e) {
  const ctx = e && (e.gmail || e.messageMetadata) || {};
  if (ctx.accessToken && typeof GmailApp !== 'undefined') {
    GmailApp.setCurrentMessageAccessToken(ctx.accessToken);
  }
  const id = String(ctx.messageId || '').trim();
  if (id) return id;

  // A thread-level context can be supplied without an individual message ID.
  // Resolve it via the Gmail service instead of guessing from the URL.
  const threadId = String(ctx.threadId || '').trim();
  if (threadId && typeof Gmail !== 'undefined') {
    try {
      const t = Gmail.Users.Threads.get('me', threadId, {format:'metadata'});
      const available = (t.messages || []).filter(m =>
        m && m.id && !(m.labelIds || []).includes('TRASH') &&
        !(m.labelIds || []).includes('SPAM'));
      if (available.length) return available[available.length - 1].id;
    } catch (error) {
      console.warn('Thread-level context could not be resolved: ' +
        String(error.message || error).slice(0, 160));
    }
  }

  const topFields = Object.keys(e || {}).filter(k => k !== 'accessToken');
  const gmailFields = Object.keys(ctx).filter(k => k !== 'accessToken');
  console.warn('Gmail message context unavailable. Event fields: ' +
    topFields.join(',') + '; context fields: ' + gmailFields.join(','));
  throw Error('Gmail did not supply a selected message ID. Expand an individual ' +
    'message, close and reopen the add-on. See Apps Script Executions if it persists.');
}
function af130Esc_(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function af130Header_(m, name) {
  const p = m && m.payload && m.payload.headers || [];
  const item = p.find(h => String(h.name).toLowerCase() === String(name).toLowerCase());
  return item ? String(item.value || '') : '';
}
function af130Mode_() {
  ensureSetup_();
  return PropertiesService.getScriptProperties().getProperty('AF_MODE') === 'LIVE'
    ? 'LIVE' : 'DRY_RUN';
}

/**
 * Fetch the conversation in two independently verified ways.
 * Gmail's contextual message is authoritative. A Threads.get response may
 * sometimes omit that message, although Messages.get can resolve it.
 * We must NOT assume the messages belong together from the UI subject alone.
 * GmailApp.getMessageById(...).getThread().getMessages() is officially
 * supported for Gmail add-ons after setting the current-message token.
 *
 * Use the union of both sources, verify EVERY member's API threadId, and
 * refuse to proceed if membership is inconsistent or cannot be established.
 * Never fabricate a thread ID from the FMfcgz URL or strip protection checks.
 */
function af132ThreadMessages_(original) {
  const threadId = String(original.threadId || '');
  const selectedId = String(original.id || '');
  if (!threadId || !selectedId) throw Error('Selected email has no stable Gmail identifiers.');

  const metaHeaders = ['Subject','From','To','Cc','Message-ID','In-Reply-To','References'];
  let apiIds = [];
  let appIds = [];
  let apiError = '';
  let appError = '';
  try {
    const thread = Gmail.Users.Threads.get('me', threadId, {
      format:'metadata', metadataHeaders:metaHeaders
    });
    if (String(thread.id || '') !== threadId) {
      throw Error('Gmail returned a different thread ID.');
    }
    apiIds = (thread.messages || []).map(m => String(m.id || '')).filter(Boolean);
  } catch (err) {
    apiError = String(err && err.message || err).slice(0, 140);
  }
  try {
    const gm = GmailApp.getMessageById(selectedId);
    if (!gm) throw Error('Selected message not accessible to GmailApp.');
    const appThread = gm.getThread();
    if (String(appThread.getId()) !== threadId) {
      throw Error('GmailApp returned a different conversation ID.');
    }
    appIds = appThread.getMessages().map(m => String(m.getId())).filter(Boolean);
  } catch (err) {
    appError = String(err && err.message || err).slice(0, 140);
  }

  const apiHasSelected = apiIds.includes(selectedId);
  const appHasSelected = appIds.includes(selectedId);
  if (!apiHasSelected && !appHasSelected) {
    console.warn('Thread lookup: API=' + apiIds.length + ' message(s), GmailApp=' +
      appIds.length + ' message(s); API error=' + apiError +
      '; GmailApp error=' + appError);
    throw Error('Cannot verify selected message in its conversation. No changes made.');
  }
  if (!apiHasSelected && appHasSelected) {
    console.warn('Thread lookup: recovered missing API message via GmailApp (' +
      apiIds.length + ' API, ' + appIds.length + ' GmailApp members).');
  }

  const ids = [...new Set([...apiIds, ...appIds, selectedId])];
  if (ids.length > AF130.maxThreadMessages) {
    throw Error('Conversation is too large to block safely. Review it manually.');
  }
  if (!ids.length) throw Error('No messages found in the selected conversation.');
  return ids.map(id => {
    const msg = Gmail.Users.Messages.get('me', id, {
      format:'metadata', metadataHeaders:metaHeaders
    });
    if (String(msg.id || '') !== id || String(msg.threadId || '') !== threadId) {
      throw Error('Conversation membership changed or disagrees between services. Nothing blocked.');
    }
    return msg;
  });
}

/**
 * Read ALL visible messages in the selected Gmail conversation BEFORE making
 * changes. Any protected duty, existing allowlist lineage, ambiguous/unreadable
 * body, or oversized thread vetoes the whole operation. Other threads unaffected.
 */
function af130PlanBlock_(messageId, expectedThreadId) {
  ensureSetup_();
  const original = Gmail.Users.Messages.get('me',messageId,{format:'metadata',
    metadataHeaders:['Subject','Message-ID','In-Reply-To','References']});
  if (expectedThreadId && original.threadId !== expectedThreadId) {
    throw Error('The selected conversation has changed. Open it again.');
  }
  if (isDiscarded_(original)) throw Error('This email is in Trash or Spam.');
  const threadId = original.threadId;
  const messages = af132ThreadMessages_(original);
  const ids = JSON.parse(PropertiesService.getScriptProperties().getProperty('AF_LABEL_IDS') || '{}');
  const known = loadKeys_();
  const details = [];
  for (const raw of messages) {
    if (isDiscarded_(raw)) continue;
    const m = normalizeMessage_(raw);
    if (m.labelIds.includes(ids[AF.labels.ALLOW]) ||
        m.labelIds.includes(ids[AF.labels.PRIORITY_REVIEW])) {
      throw Error('Conversation contains a protected or manually allowed message.');
    }
    if (lineageKeys_(m).some(k => known.allowed.has(k))) {
      throw Error('Conversation includes a protected reply chain.');
    }
    // Academic subjects get the same hard protection even on an explicit click.
    if (protectedDutyKind_(m.subject,'') || AF.importantSubject.test(m.subject)) {
      throw Error('Protected academic/duty subject detected. Nothing blocked.');
    }
    let body = '';
    try {
      const full = Gmail.Users.Messages.get('me',m.id,{format:'full'});
      if (isDiscarded_(full)) continue;
      body = plainText_(full.payload,AF130.maxBodyChars);
      if (!String(body).trim() && typeof GmailApp !== 'undefined') {
        // Some Gmail MIME payloads are returned as decoded arrays or are unusual.
        // GmailApp is a safer read-only fallback before denying a block.
        const fallback = GmailApp.getMessageById(m.id);
        body = fallback ? fallback.getPlainBody() : '';
      }
    } catch (err) {
      throw Error('Cannot safely inspect a message. No changes made.');
    }
    if (!String(body).trim()) throw Error('Unreadable email body. Nothing blocked.');
    if (protectedDutyKind_(m.subject,body)) {
      throw Error('Admission-test or invigilation duty detected. Nothing blocked.');
    }
    details.push(m);
  }
  if (!details.length) throw Error('No eligible messages in this conversation.');
  return {threadId, details, ids, known,
    inboxCount:details.filter(m=>m.labelIds.includes('INBOX')).length};
}

/**
 * The only mutation entry point. Always locks against the one-minute scanner,
 * and keeps global DRY_RUN absolutely side-effect-free.
 */
function af130BlockByMessageId_(messageId, expectedThreadId) {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) throw Error('Mailbox scan is busy. Try again shortly.');
  try {
    const plan = af130PlanBlock_(messageId, expectedThreadId || '');
    const mode = af130Mode_();
    if (mode !== 'LIVE') {
      console.log('DRY_RUN: ' + plan.inboxCount + ' inbox messages eligible in thread ' + plan.threadId);
      return {mode:'DRY_RUN', archived:0, inboxCount:plan.inboxCount};
    }
    // Write stable IDs BEFORE archiving, so deleting originals doesn't erase
    // the reply-chain ancestry. This may also add IDs for already archived mail.
    plan.details.forEach(m => {
      rememberKeys_(AF_DB.BLOCKED,lineageKeys_(m),m,
        'GMAIL_ONE_CLICK_BLOCK',plan.known.blocked);
    });
    let archived = 0;
    for (const m of plan.details) {
      if (!m.labelIds.includes('INBOX')) continue;
      // Re-read the message just before changing labels; another workflow may
      // have moved it, or the protected labels may have changed in the meantime.
      const latest = Gmail.Users.Messages.get('me',m.id,{format:'metadata',
        metadataHeaders:['Subject']});
      if (isDiscarded_(latest) || !(latest.labelIds||[]).includes('INBOX')) continue;
      if ((latest.labelIds||[]).includes(plan.ids[AF.labels.ALLOW]) ||
          (latest.labelIds||[]).includes(plan.ids[AF.labels.PRIORITY_REVIEW])) continue;
      modifyLabels_(m.id,
        [plan.ids[AF.labels.FORCE_BLOCK],plan.ids[AF.labels.SUPPRESSED],plan.ids[AF.labels.CHECKED]],
        ['INBOX','UNREAD',plan.ids[AF.labels.AI_KEEP],plan.ids[AF.labels.REVIEW],
         plan.ids[AF.labels.PENDING],plan.ids[AF.labels.RULE_NOISE]]);
      log_(m,'ARCHIVED','GMAIL_ONE_CLICK_BLOCK');
      archived++;
    }
    return {mode:'LIVE',archived,inboxCount:plan.inboxCount,threadId:plan.threadId};
  } finally {
    lock.releaseLock();
  }
}

/** Upgrade without resetting the ledger, triggers, or user's LIVE/DRY_RUN mode.
 * Run when adding the new files, then use Deploy > Test deployments > Install.
 * Explicitly switches to DRY_RUN so installation cannot unexpectedly archive.
 */
function upgradeFirewallV130() {
  ensureSetup_();
  PropertiesService.getScriptProperties().setProperty('AF_MODE','DRY_RUN');
  console.log('v1.3.0 installed. Existing ledger, nested labels and Studio flow retained.');
  console.log('DRY_RUN active. Deploy > Test deployments > Install to add the Gmail sidebar button.');
}

/** Synthetic, no mailbox access. Run to confirm the hard-protection regex. */
function testOneClickSafetyV130() {
  const cases = [
    ['Invitation: Example University admission test duty',true],
    ['Invigilation volunteers needed',true],
    ['ভর্তি পরীক্ষার ডিউটি',true],
    ['University yoga session invitation',false],
    ['Invitation to my book launch',false]
  ];
  cases.forEach(([subject,expected])=>{
    const observed = !!protectedDutyKind_(subject,'');
    if (observed!==expected)throw Error('Protection mismatch: '+subject);
    console.log('PASS: '+subject);
  });
}
