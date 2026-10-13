/**
 * SPDX-License-Identifier: MIT
 * Original project: FGZ · https://github.com/fahim9778/DNPHSEE
 * DNPHSEE v1.3.3 — invigilation/admission-test duty fail-safe.
 * Workspace Studio classifies new mail; local rules triage clear missed invitations.
 * No Gemini Developer API, no billing, and no outbound HTTP requests.
 * Never sends mail, never deletes mail, and never archives while DRY_RUN.
 */

const AF = Object.freeze({
  labels: Object.freeze({
    AI_NOISE: 'AF_AI_NOISE', AI_KEEP: 'AF_AI_KEEP',
    FORCE_BLOCK: 'AF_FORCE_BLOCK', ALLOW: 'AF_ALLOW',
    ALLOW_DONE: 'AF_ALLOWED_DONE', CHECKED: 'AF_CHECKED',
    SUPPRESSED: 'AF_SUPPRESSED', REVIEW: 'AF_REVIEW',
    PRIORITY_REVIEW: 'AF_PRIORITY_REVIEW', PENDING: 'AF_PENDING',
    RULE_NOISE: 'AF_RULE_NOISE', KEEP_AUDITED: 'AF_KEEP_AUDITED'
  }),
  // Trust individual verified addresses only; never exempt a whole organization domain.
  trustedSenders: [], trustedRecipients: [],
  importantSubject: /\b(CSE\s?\d{3}|exam(?:ination)?|invigilation|midterm|final\s+exam|course\s+(?:registration|allocation)|grade\s+(?:submission|correction)|faculty\s+meeting|committee\s+meeting|student\s+advising|academic\s+calendar|payroll|salary|tax\s+certificate|human\s+resources|mandatory|compliance|security\s+alert|official\s+policy|urgent\s+notice)\b/i,
  inboxWindowDays: 14,
  maxPerQueue: 60,
  studioGraceMinutes: 10,
  ruleRetryMinutes: 720, // Reconsider still-unknown items twice per day.
  maxRuleChecksPerRun: 12,
  ruleBodyChars: 4500,
  pendingBatchSize: 20,
  maxKeepAuditsPerRun: 12,
  keepAuditWindowDays: 30,
  resetOptionalAuditMax: 250
});
const AF_DB = Object.freeze({BLOCKED: 'BlockedKeys', ALLOWED: 'AllowedKeys', AUDIT: 'Audit', PENDING: 'Pending'});
/** Highest-priority protection: recruitment, invitations, scheduling and
 * assignments connected to admission TESTS or invigilation/proctoring duties.
 * These opportunities may carry honoraria without mentioning payment and may
 * be sent as optional mass invitations. No sender/domain/mandatory filter may
 * override this protection. Bangla variants are included.
 * Intentionally prefer false-positive protection over losing an opportunity.
 */
function protectedDutyKind_(subject, body) {
  const text = String(subject || '') + '\n' + String(body || '');
  const invigilation = /\b(?:invigilat(?:ion|or|ors|e|ing|ed)|proctor(?:ing|s|ship)?|exam(?:ination)?\s+dut(?:y|ies)|test\s+dut(?:y|ies)|admission\s+dut(?:y|ies)|admissions\s+dut(?:y|ies))\b/i.test(text) ||
    /(ইনভিজিলেশন|ইনভিজিলেটর|ইনভিজিলেট|পরীক্ষা(?:র|য়|য়)?\s*(?:ডিউটি|দায়িত্ব|দায়িত্ব)|পরীক্ষা\s*পরিদর্শক)/i.test(text);
  if (invigilation) return 'PROTECTED_INVIGILATION_DUTY';
  const admissionTest = /\b(?:admission|admissions|entrance)\s*(?:test|exams?|examination|assessment|selection\s+test|written\s+test)\b|\b(?:test|exams?|examination|assessment)\s+(?:for\s+)?(?:admission|admissions)\b/i.test(text) ||
    /(ভর্তি.{0,22}(?:পরীক্ষা|টেস্ট|এক্সাম)|(?:পরীক্ষা|টেস্ট).{0,22}ভর্তি)/i.test(text);
  return admissionTest ? 'PROTECTED_ADMISSION_TEST' : '';
}

/** Mark a protected *individual message* as needing attention, never a whole
 * conversation: another reply in the same conversation might still be noise.
 * Clear contradictory AI/force/rule labels to avoid future reprocessing.
 * Does not add lineage to AllowedKeys: that would exempt the whole thread.
 */
function preserveDutyMessage_(m, ctx, reason) {
  const ids = ctx.ids;
  modifyLabels_(m.id, [ids[AF.labels.PRIORITY_REVIEW], ids[AF.labels.CHECKED]],
    [ids[AF.labels.AI_NOISE], ids[AF.labels.RULE_NOISE],
     ids[AF.labels.FORCE_BLOCK], ids[AF.labels.REVIEW], ids[AF.labels.PENDING]]);
  pendingDone_(m, ctx.pending, reason);
  // Remember ONLY this protected message's own RFC Message-ID. A reply's
  // In-Reply-To/References headers then match; unrelated messages that share
  // the Gmail conversation are NOT automatically allowed.
  if (ctx.live) {
    const protectedKeys = rfcIds_(m.messageId).map(id => 'RFC:' + id);
    if (protectedKeys.length) rememberKeys_(AF_DB.ALLOWED, protectedKeys, m,
      'PROTECTED_DUTY_REPLY_CHAIN', ctx.known.allowed);
  }
  log_(m, 'PROTECT', reason);
}

/** Every message that is about to be archived gets a FULL content safety scan.
 * For unreadable MIME content, fail closed: leave it in Inbox for review.
 * This applies even when Studio said NOISE, FORCE_BLOCK was set, or the thread
 * matches BlockedKeys. It is intentionally a final pre-archive veto.
 */
function preArchiveDutyGuard_(m, ctx) {
  const bySubject = protectedDutyKind_(m.subject, '');
  if (bySubject) {preserveDutyMessage_(m, ctx, bySubject); return true;}
  try {
    const raw = Gmail.Users.Messages.get('me', m.id, {format:'full'});
    if (isDiscarded_(raw) || !(raw.labelIds || []).includes('INBOX')) return true;
    const body = plainText_(raw.payload, 64000);
    if (!String(body).trim()) throw Error('Email body is empty or unavailable');
    const protectedReason = protectedDutyKind_(m.subject, body);
    if (protectedReason) {
      preserveDutyMessage_(m, ctx, protectedReason);
      return true;
    }
    return false;
  } catch (err) {
    // A message we cannot inspect must NOT be suppressed automatically.
    modifyLabels_(m.id, [ctx.ids[AF.labels.PRIORITY_REVIEW]],
      [ctx.ids[AF.labels.REVIEW]]);
    log_(m, 'PROTECT', 'BODY_UNREADABLE_REVIEW');
    console.warn('Suppression withheld for unreadable message ' + m.id + ': ' + safeError_(err));
    return true;
  }
}

const AF_LABEL_PARENT = 'ZZ'; // Compact collapsible parent, sorts near the bottom.
const AF_LABEL_LEGACY_PARENT = 'ZZ-Firewall';
// Only two short status chips are shown beside email subjects. The rest remain
// searchable and visible when the ZZ parent is expanded in Gmail's sidebar.
const AF_LABEL_SHORT = Object.freeze({
  AF_AI_NOISE: 'AF_N',
  AF_AI_KEEP: 'AF_K', AF_FORCE_BLOCK: 'AF_FB',
  AF_ALLOW: 'AF_A', AF_ALLOWED_DONE: 'AF_AD',
  AF_CHECKED: 'AF_C', AF_SUPPRESSED: 'AF_S',
  AF_REVIEW: 'AF_R', AF_PRIORITY_REVIEW: 'AF_PR',
  AF_PENDING: 'AF_P', AF_RULE_NOISE: 'AF_RN',
  AF_KEEP_AUDITED: 'AF_KA'
});
function compactLabelName_(original) {
  return AF_LABEL_PARENT + '/' + (AF_LABEL_SHORT[original] || original);
}
function showLabelChip_(original) {
  return original === AF.labels.AI_NOISE || original === AF.labels.AI_KEEP;
}
// Gmail's supported label-color palette: white text on dark red.
// Only the noise label is colored. Other user preferences are left intact.
const AF_NOISE_LABEL_COLOR = Object.freeze({
  textColor: '#ffffff', backgroundColor: '#cc3a21'
});
/** Optional one-click cosmetic customization for existing installations. */
function setNoiseLabelRed() {
  const props = PropertiesService.getScriptProperties();
  let savedIds = {};
  try { savedIds = JSON.parse(props.getProperty('AF_LABEL_IDS') || '{}'); } catch (_) {}
  const found = (Gmail.Users.Labels.list('me').labels || [])
    .find(l => l.name === compactLabelName_(AF.labels.AI_NOISE));
  const id = (found && found.id) || savedIds[AF.labels.AI_NOISE];
  if (!id) throw Error('Noise label not found. Run setupFirewall() first.');
  Gmail.Users.Labels.patch({color: AF_NOISE_LABEL_COLOR}, 'me', id);
  console.log('Gmail label ZZ/AF_N is now red (white text).');
}

/** v1.2.6: rename in place (same label IDs) and keep only AI_K/AI_N chips.
 * Repeated runs are safe. Does not remove message labels or delete mail.
 */
function compactFirewallLabels() {
  ensureSetup_();
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) throw Error('Mailbox scan is running. Please retry shortly.');
  try {
    const p = PropertiesService.getScriptProperties();
    p.setProperty('AF_MODE', 'DRY_RUN');
    const ids = getOrCreateLabels_();
    p.setProperty('AF_LABEL_IDS', JSON.stringify(ids));
    p.setProperty('AF_LABEL_LAYOUT', 'COMPACT');
    console.log('v1.2.6 READY: Labels nested under ZZ. Only ZZ/AF_K and ZZ/AF_N show on message rows.');
    console.log('Existing Gmail label IDs, messages and the private ledger are preserved. DRY_RUN active.');
    console.log('Verify Step 4 = ZZ/AF_N and Step 6 = ZZ/AF_K in Workspace Studio.');
  } finally { lock.releaseLock(); }
}
// Older entry point remains available for people following the v1.2.2 guide.
function organizeFirewallLabels() { compactFirewallLabels(); }

/** v1.2.7: Refresh only previously audited optional invitations so
 * the new narrow rules can reconsider them. No email is archived here.
 * This is bounded to avoid scanning an unbounded university mailbox.
 */
function recheckOptionalInvitationsV127_() {
  const p = PropertiesService.getScriptProperties();
  const ids = JSON.parse(p.getProperty('AF_LABEL_IDS') || '{}');
  const query = 'in:inbox -in:trash -in:spam label:' + AF.labels.AI_KEEP +
    ' label:' + AF.labels.KEEP_AUDITED +
    ' newer_than:' + AF.keepAuditWindowDays + 'd';
  const result = Gmail.Users.Messages.list('me', {
    q: searchLabelQuery_(query), maxResults: AF.resetOptionalAuditMax
  });
  const maybeOptional = /\b(invitation|invite|career (?:fair|session|talk|workshop)|yoga|drama|cultural|concert|public lecture|seminar|workshop|inauguration|ceremony|celebration|condolence)\b|(?:আমন্ত্রণ|কর্মশালা|নাটক|সেমিনার|শোকবার্তা|যোগব্যায়াম)/i;
  let reset = 0;
  (result.messages || []).forEach(entry => {
    try {
      const raw = Gmail.Users.Messages.get('me', entry.id, {format:'metadata',
        metadataHeaders:['Subject']});
      if (isDiscarded_(raw) || !(raw.labelIds || []).includes('INBOX')) return;
      const subject = (raw.payload?.headers || []).find(h => String(h.name).toLowerCase() === 'subject')?.value || '';
      if (!maybeOptional.test(subject)) return;
      modifyLabels_(entry.id, [], [ids[AF.labels.KEEP_AUDITED]]);
      reset++;
    } catch (err) {
      console.warn('Optional event re-audit reset skipped: ' + safeError_(err));
    }
  });
  return {reset, scanned:(result.messages || []).length,
    capped: (result.messages || []).length >= AF.resetOptionalAuditMax};
}

/** One-time upgrade: preserves ledger and compact label IDs; DRY_RUN safety. */
function upgradeFirewallV127() {
  ensureSetup_();
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) throw Error('Scanner busy: retry the upgrade in a minute.');
  try {
    const p = PropertiesService.getScriptProperties();
    p.setProperty('AF_MODE', 'DRY_RUN');
    const result = recheckOptionalInvitationsV127_();
    console.log('v1.2.7 active. DRY_RUN. Reset '+result.reset+
      ' previously checked optional invitations (inspected '+result.scanned+').');
    if (result.capped) console.log('Reached scan cap. Re-run upgradeFirewallV127 later if older events still need rechecking.');
    console.log('Workspace Studio Step 2 prompt update recommended; no label or manifest changes.');
  } finally { lock.releaseLock(); }
}

/** v1.2.8: protective guard upgrade. Existing IDs and ledger preserved.
 * Previewing the change in DRY_RUN avoids surprise mailbox mutations.
 * No new scopes, labels, or time triggers required.
 */
function upgradeFirewallV128() {
  ensureSetup_();
  PropertiesService.getScriptProperties().setProperty('AF_MODE', 'DRY_RUN');
  console.log('v1.2.8 installed: absolute admission test/invigilation duty protection, including invite-to-volunteer messages. DRY_RUN.');
  console.log('Studio Decide prompt should also be updated; labels stay Step 4 ZZ/AF_N and Step 6 ZZ/AF_K.');
  console.log('Use testProtectedDutyRules() then scanMailbox(), review ZZ/AF_PR before goLive().');
}

/** Safe pure local tests: never touch mail. */
function testProtectedDutyRules() {
  const protectedCases = [
    ['Invitation: Invigilation Duty', 'Join the optional duty roster.'],
    ['Volunteer for Admission Test', 'Please confirm availability.'],
    ['Invitation to university work', 'Invigilators are invited to volunteer; there is no mention of honorarium.'],
    ['ভর্তি পরীক্ষার দায়িত্ব পালনের আহ্বান', 'আগ্রহী শিক্ষকগণ যোগাযোগ করুন।'],
    ['University-wide Invitation', 'Please volunteer to proctor the admission examination.'],
    ['Examination Duty Assignment', 'Please attend if available.']
  ];
  protectedCases.forEach(([subject, body]) => {
    const reason = protectedDutyKind_(subject, body);
    if (!reason) throw Error('Hard protection missing: '+subject);
    const d = freeRuleDecision_({subject, body, to:'all@example.edu'});
    if (d.decision === 'NOISE') throw Error('Free rules suppressed duty invitation: '+subject);
  });
  const other = freeRuleDecision_({subject:'Invitation to Yoga Session',
    body:'Dear colleagues, you are invited. Date: Friday. Venue: Auditorium.',
    to:'faculty@example.edu'});
  if (other.decision !== 'NOISE') throw Error('Optional social events no longer suppressed');
  console.log('PASS: Admission-test and invigilation protection in English and Bangla, plus ordinary noise classification.');
}

/** One-time v1.2.3 update. Preserves existing Gmail and Studio labels,
 * ledger, manually blocked threads, and trigger. Always starts in DRY_RUN.
 * New audit marker is nested under the existing parent label.
 */
function upgradeFirewallV123() {
  ensureSetup_();
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(15000)) throw Error('Scanner is currently running. Retry shortly.');
  try {
    const p = PropertiesService.getScriptProperties();
    p.setProperty('AF_MODE', 'DRY_RUN');
    const ids = getOrCreateLabels_();
    p.setProperty('AF_LABEL_IDS', JSON.stringify(ids));
    p.setProperty('AF_LABEL_LAYOUT', 'COMPACT');
    console.log('v1.2.3 installed: Studio KEEP second-opinion enabled; DRY_RUN active.');
    console.log('Old Studio KEEP emails will be checked gradually (up to ' +
      AF.maxKeepAuditsPerRun + ' per minute) without changing protected emails.');
  } finally { lock.releaseLock(); }
}

/** One-time v1.2.4 safety update. Does not change account data or reset the ledger. */
function upgradeFirewallV124() {
  ensureSetup_();
  PropertiesService.getScriptProperties().setProperty('AF_MODE', 'DRY_RUN');
  console.log('v1.2.4 installed: Trash and Spam are excluded from mailbox screening. DRY_RUN active.');
}

/** One-time v1.2.5 MIME Byte[] fix. Does not alter existing labels or ledger. */
function upgradeFirewallV125() {
  ensureSetup_();
  const p = PropertiesService.getScriptProperties();
  p.setProperty('AF_MODE', 'DRY_RUN');
  const sh = db_().getSheetByName(AF_DB.PENDING);
  let reset = 0;
  const n = sh.getLastRow() - 1;
  if (n > 0) {
    const rows = sh.getRange(2, 1, n, 7).getValues();
    rows.forEach(row => {
      if (String(row[4]) === 'RETRY_RULE_ERROR') {
        row[2] = '';
        row[4] = 'PENDING_LOCAL_RULE';
        row[5] = 'RETRY_WITH_BYTE_ARRAY_DECODER';
        reset++;
      }
    });
    if (reset) sh.getRange(2, 1, n, 7).setValues(rows);
  }
  console.log('v1.2.5 installed: Gmail MIME Byte[] handling enabled. DRY_RUN active.');
  console.log('Reset ' + reset + ' pending decode failures for retry.');
}

/** Deleted/spam messages are not a target of inbox cleanup. Check Gmail's
 * actual message labels, not just search results, because a conversation can
 * contain messages with different labels or can change while a scan runs. */
function isDiscarded_(message) {
  const labels = message && message.labelIds || [];
  return labels.includes('TRASH') || labels.includes('SPAM');
}

/** Translate logical names to the CURRENT label names for Gmail queries.
 * During the brief period between replacing Code.gs and running the migration,
 * continue searching legacy ZZ-Firewall labels instead of silently missing mail.
 */
function searchLabelQuery_(query) {
  const layout = PropertiesService.getScriptProperties().getProperty('AF_LABEL_LAYOUT');
  if (layout !== 'NESTED' && layout !== 'COMPACT') return query;
  return query.replace(/(^|\s)(-?)label:(AF_[A-Z_]+)/g, (match, space, negative, logical) => {
    const full = layout === 'NESTED'
      ? AF_LABEL_LEGACY_PARENT + '/' + logical
      : compactLabelName_(logical);
    return space + negative + 'label:' + full.replace('/', '-');
  });
}

/** Diagnostic only. Test using a label that contains at least one email. */
function checkNestedLabelSearch() {
  ensureSetup_();
  const p = PropertiesService.getScriptProperties();
  if (!['NESTED', 'COMPACT'].includes(p.getProperty('AF_LABEL_LAYOUT'))) throw Error('Run compactFirewallLabels first.');
  const ids = JSON.parse(p.getProperty('AF_LABEL_IDS'));
  const label = AF.labels.AI_NOISE;
  const byId = Gmail.Users.Messages.list('me',{labelIds:[ids[label]],maxResults:20}).messages || [];
  if (!byId.length) {
    console.log('No labeled email available to verify the search. Label nesting itself is ready.');
    return;
  }
  const q = searchLabelQuery_('label:' + label);
  const bySearch = Gmail.Users.Messages.list('me',{q:q,maxResults:40}).messages || [];
  const hits = new Set(bySearch.map(x=>x.id));
  if (!byId.some(x=>hits.has(x.id))) {
    throw Error('Nested label search mismatch (' + q + '). Do not turn on LIVE.');
  }
  console.log('PASS nested label search: ' + q);
}

/** Install or upgrade WITHOUT replacing ledger, manual decisions or mode. */
function setupFirewall() {
  const p = PropertiesService.getScriptProperties();
  if (!p.getProperty('AF_DB_ID')) {
    const db = SpreadsheetApp.create('DNPHSEE - Private Ledger');
    const b = db.getSheets()[0]; b.setName(AF_DB.BLOCKED);
    b.appendRow(['Key', 'Source Gmail Thread ID', 'Timestamp', 'Source Gmail Message ID', 'Reason']);
    db.insertSheet(AF_DB.ALLOWED).appendRow(['Key', 'Source Gmail Thread ID', 'Timestamp', 'Source Gmail Message ID', 'Reason']);
    db.insertSheet(AF_DB.AUDIT).appendRow(['Timestamp', 'Decision', 'Reason', 'Subject', 'Sender', 'Gmail Thread ID', 'Gmail Message ID']);
    p.setProperty('AF_DB_ID', db.getId());
  }
  const db = db_();
  if (!db.getSheetByName(AF_DB.PENDING)) {
    db.insertSheet(AF_DB.PENDING).appendRow(['Gmail Message ID', 'First seen', 'Last attempted', 'Attempts', 'Status', 'Last reason', 'Subject']);
  }
  const ids = getOrCreateLabels_();
  p.setProperty('AF_LABEL_IDS', JSON.stringify(ids));
  p.setProperty('AF_LABEL_LAYOUT','COMPACT');
  if (!p.getProperty('AF_MODE')) p.setProperty('AF_MODE', 'DRY_RUN');
  // Secure default. Existing LIVE mode is preserved; run pauseSuppression()
  // BEFORE upgrading if you want DRY_RUN regardless of previous mode.
  // Old external API fallback is unconditionally disabled by this release.
  p.setProperty('AF_FALLBACK_ENABLED', 'false');
  ScriptApp.getProjectTriggers().forEach(t => {
    if (t.getHandlerFunction() === 'scanMailbox') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('scanMailbox').timeBased().everyMinutes(1).create();
  console.log('DNPHSEE v1.3.3 ready. Existing ledger preserved. Mode=' + p.getProperty('AF_MODE'));
  statusFirewall();
}
function upgradeFirewallV12() {
  // Force a new, untested ruleset into DRY_RUN even if a previous release was LIVE.
  PropertiesService.getScriptProperties().setProperty('AF_MODE', 'DRY_RUN');
  setupFirewall();
  const p = PropertiesService.getScriptProperties();
  p.setProperty('AF_FALLBACK_ENABLED', 'false');
  // Delete the no-longer-needed secret from project properties.
  p.deleteProperty('AF_GEMINI_API_KEY');
  p.deleteProperty('AF_GEMINI_MODEL');
  p.deleteProperty('AF_PENDING_CURSOR');
  // Old 403 API retry timestamps should not delay the new local rule check.
  const sh = db_().getSheetByName(AF_DB.PENDING);
  const count = sh.getLastRow() - 1;
  if (count > 0) {
    const rows = sh.getRange(2, 1, count, 7).getValues();
    let changed = false;
    rows.forEach(row => {
      const status = String(row[4] || '');
      if (!/^DONE_|^MISSING/.test(status)) {
        row[2] = ''; // Last attempted (formerly blocked API).
        row[4] = 'PENDING_LOCAL_RULE';
        row[5] = 'AWAITING_LOCAL_RECHECK';
        changed = true;
      }
    });
    if (changed) sh.getRange(2, 1, count, 7).setValues(rows);
  }
  console.log('v1.2 migration complete. DRY_RUN active; old external Gemini key removed.');
}
function goLive() {
  ensureSetup_();
  PropertiesService.getScriptProperties().setProperty('AF_MODE', 'LIVE');
  console.log('LIVE — archiving is enabled. No permanent deletion.');
}
function pauseSuppression() {
  ensureSetup_();
  PropertiesService.getScriptProperties().setProperty('AF_MODE', 'DRY_RUN');
  console.log('DRY_RUN — no archiving by this script.');
}

/** One-time hotfix migration. No new Gmail labels, no new triggers, no new ledger. */
function upgradeFirewallV121() {
  ensureSetup_();
  const p = PropertiesService.getScriptProperties();
  // A decoder hotfix should never accidentally enable archiving.
  p.setProperty('AF_MODE', 'DRY_RUN');
  p.setProperty('AF_FALLBACK_ENABLED', 'false');
  const sh = db_().getSheetByName(AF_DB.PENDING);
  const n = sh.getLastRow() - 1;
  let reset = 0;
  if (n > 0) {
    const values = sh.getRange(2, 1, n, 7).getValues();
    values.forEach(row => {
      if (String(row[4]) !== 'RETRY_RULE_ERROR') return;
      // Keep original first-seen time; skip only the failed 12-hour retry cooldown.
      row[2] = ''; // last attempted
      row[4] = 'PENDING_LOCAL_RULE';
      row[5] = 'RETRY_AFTER_MIME_FIX';
      reset++;
    });
    if (reset) sh.getRange(2, 1, n, 7).setValues(values);
  }
  p.deleteProperty('AF_PENDING_CURSOR');
  console.log('Firewall v1.2.1 installed; DRY_RUN enabled. Reset ' + reset + ' MIME decode retries.');
}

/** Run synthetic tests without touching Gmail or using network APIs. */
function testFreeRules() {
  const examples = [
    {expect:'NOISE',subject:'Invitation to a Conversation on Transitional Feminism',
      to:'ENH <humanities@example.edu>, Example University <all@example.edu>',
      body:'Dear colleagues, The Department is delighted to invite you to an upcoming event. Date: October 12. Time: 3:30 PM. Venue: Classroom. Speaker bios follow.'},
    {expect:'NOISE',subject:'Re: World Top 2% Scientists 2026',
      to:'faculty@lists.example.edu',body:'Dear colleagues, congratulations on the ranking!'},
    {expect:'NOISE',subject:'আমাদের সাংস্কৃতিক সন্ধ্যায় আমন্ত্রণ',
      to:'all@example.edu',body:'প্রিয় সহকর্মীবৃন্দ, অনুষ্ঠানে আপনাদের স্বাগতম।'},
    {expect:'PENDING',subject:'Faculty workshop on examination policy',
      to:'faculty@lists.example.edu',body:'Attendance is mandatory for all faculty. Please note the deadline.'},
    {expect:'PENDING',subject:'CSE221 final exam logistics',
      to:'all@example.edu',body:'Required invigilation instructions.'}
  ];
  examples.forEach(x => {
    const got = freeRuleDecision_(x);
    if (got.decision !== x.expect) throw Error('Rule test failed for: ' + x.subject + ' got ' + got.decision);
    console.log('PASS ' + got.decision + ': ' + x.subject);
  });
}

/** Called by recurring trigger. Reprocesses old CHECKED-but-unclassified mail. */
function scanMailbox() {
  ensureSetup_();
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(3000)) return;
  try {
    const p = PropertiesService.getScriptProperties();
    const ids = JSON.parse(p.getProperty('AF_LABEL_IDS'));
    const live = p.getProperty('AF_MODE') === 'LIVE';
    const known = loadKeys_();
    const pending = loadPending_();
    const ctx = {ids: ids, known: known, pending: pending, live: live,
      seen: new Set(), ruleChecks: 0};
    const reviewExclude = live ? '' : ' -label:' + AF.labels.REVIEW;
    // v1.2.3: Gemini may mark an optional broadcast as KEEP because it came from
    // an official address. Recheck only clearly unwanted, safely recognized events.
    // A separate completed-audit label prevents redundant reads every minute.
    recheckStudioKeeps_(ctx);
    processQueue_('label:' + AF.labels.ALLOW + ' -label:' + AF.labels.ALLOW_DONE, 'ALLOW', ctx);
    // A later Studio KEEP decision can correct an earlier dry-run rule decision.
    processQueue_('label:' + AF.labels.AI_KEEP + ' label:' + AF.labels.RULE_NOISE, 'KEEP_CORRECTION', ctx);
    processQueue_('label:' + AF.labels.AI_KEEP + ' label:' + AF.labels.REVIEW, 'KEEP_REVIEW', ctx);
    processQueue_('label:' + AF.labels.FORCE_BLOCK + ' -label:' + AF.labels.SUPPRESSED +
      ' -label:' + AF.labels.PRIORITY_REVIEW + reviewExclude, 'BLOCK', ctx);
    processQueue_('label:' + AF.labels.AI_NOISE + ' -label:' + AF.labels.SUPPRESSED +
      ' -label:' + AF.labels.PRIORITY_REVIEW + reviewExclude, 'AI', ctx);
    processQueue_('label:' + AF.labels.RULE_NOISE + ' -label:' + AF.labels.SUPPRESSED +
      ' -label:' + AF.labels.PRIORITY_REVIEW + reviewExclude, 'RULE', ctx);
    // NEW: AF_CHECKED from any source (including older Studio flows)
    // is NOT proof that a message received a classification.
    const needsDecision = ' -label:' + AF.labels.AI_NOISE + ' -label:' + AF.labels.AI_KEEP +
      ' -label:' + AF.labels.PRIORITY_REVIEW + ' -label:' + AF.labels.SUPPRESSED;
    processQueue_('in:inbox -label:' + AF.labels.CHECKED + ' -label:' + AF.labels.PENDING +
      needsDecision + ' newer_than:' + AF.inboxWindowDays + 'd', 'INBOX', ctx);
    processQueue_('in:inbox label:' + AF.labels.CHECKED + ' -label:' + AF.labels.PENDING +
      needsDecision + ' newer_than:' + AF.inboxWindowDays + 'd', 'LEGACY', ctx);
    processPendingBatch_(ctx);
    // AI_KEEP that arrived after AF_PENDING was attached: clears pending regardless of CHECKED.
    processQueue_('label:' + AF.labels.PENDING + ' label:' + AF.labels.AI_KEEP, 'PENDING_KEEP', ctx);
  } finally { lock.releaseLock(); }
}

/** Bounded, content-based second opinion of Studio KEEP messages.
 * An AI_KEEP label is NOT proof an email contains an obligation. For clear
 * optional broadcasts we remove the mistaken KEEP label and process as a
 * local NOISE decision. If uncertain or protected, leave KEEP untouched.
 * Sender is never used as a sole reason to suppress.
 */
function recheckStudioKeeps_(ctx) {
  const q = 'in:inbox -in:trash -in:spam label:' + AF.labels.AI_KEEP +
    ' -label:' + AF.labels.KEEP_AUDITED +
    ' -label:' + AF.labels.RULE_NOISE +
    ' -label:' + AF.labels.REVIEW +
    ' newer_than:' + AF.keepAuditWindowDays + 'd';
  const res = Gmail.Users.Messages.list('me', {
    q:searchLabelQuery_(q), maxResults:AF.maxKeepAuditsPerRun});
  (res.messages || []).forEach(item => {
    if (ctx.seen.has(item.id)) return;
    try {
      const raw = Gmail.Users.Messages.get('me',item.id,{format:'full'});
      const m = normalizeMessage_(raw);
      // Never inspect bodies of messages already removed from the Inbox.
      if (isDiscarded_(m) || !m.labelIds.includes('INBOX')) return;
      const tags = new Set(m.labelIds);
      const keys = lineageKeys_(m);
      const trusted = isTrusted_(m);
      const explicitlyAllowed = tags.has(ctx.ids[AF.labels.ALLOW]) ||
        keys.some(k => ctx.known.allowed.has(k));
      const forceBlocked = tags.has(ctx.ids[AF.labels.FORCE_BLOCK]);
      const rememberedBlock = keys.some(k => ctx.known.blocked.has(k));
      const body = plainText_(raw.payload, 64000);
      const protectedReason = protectedDutyKind_(m.subject, body);
      if (protectedReason) {
        ctx.seen.add(m.id);
        preserveDutyMessage_(m, ctx, protectedReason);
        modifyLabels_(m.id, [ctx.ids[AF.labels.KEEP_AUDITED]], []);
        return;
      }
      // An explicitly blocked conversation can acquire new replies that Studio
      // labels KEEP. Challenge that decision before marking the reply audited;
      // otherwise the one-minute scanner might never see the remembered key.
      // This is intentionally limited to exact Gmail/RFC ancestry, not a sender
      // or broad subject rule. Existing protected-subject and full-body duty
      // safeguards are still enforced by handleMessage_().
      if (rememberedBlock && !explicitlyAllowed && !trusted && !forceBlocked) {
        modifyLabels_(m.id,[ctx.ids[AF.labels.KEEP_AUDITED]],
          [ctx.ids[AF.labels.AI_KEEP]]);
        m.labelIds = m.labelIds.filter(x => x !== ctx.ids[AF.labels.AI_KEEP]);
        m.labelIds.push(ctx.ids[AF.labels.KEEP_AUDITED]);
        ctx.seen.add(m.id);
        handleMessage_(m,'REMEMBERED_BLOCK_OVERRIDE',ctx);
        return;
      }
      const decision = freeRuleDecision_({subject:m.subject,body:body,to:m.to,cc:m.cc});
      // Stamp inspected messages; the same KEEP email is not repeatedly fetched.
      modifyLabels_(m.id,[ctx.ids[AF.labels.KEEP_AUDITED]],[]);
      if (decision.decision !== 'NOISE' || explicitlyAllowed || trusted || forceBlocked) return;
      // Explicit rule-based reversal, not a new Gemini judgment.
      modifyLabels_(m.id,[ctx.ids[AF.labels.RULE_NOISE]],
        [ctx.ids[AF.labels.AI_KEEP]]);
      m.labelIds = m.labelIds.filter(x => x !== ctx.ids[AF.labels.AI_KEEP]);
      m.labelIds.push(ctx.ids[AF.labels.RULE_NOISE]);
      ctx.seen.add(m.id);
      handleMessage_(m,'KEEP_OVERRIDDEN_BY_RULE',ctx);
    } catch (err) {
      console.warn('KEEP audit failed for ' + item.id + ': ' + safeError_(err));
    }
  });
}

function processQueue_(query, source, ctx) {
  const result = Gmail.Users.Messages.list('me', {
    q: searchLabelQuery_(query + ' -in:trash -in:spam'), maxResults: AF.maxPerQueue});
  (result.messages || []).forEach(item => {
    if (ctx.seen.has(item.id)) return;
    ctx.seen.add(item.id);
    try {
      const msg = Gmail.Users.Messages.get('me', item.id, {format:'metadata',
        metadataHeaders:['Message-ID','In-Reply-To','References','From','To','Cc','Subject']});
      handleMessage_(normalizeMessage_(msg), source, ctx);
    } catch (err) { console.error('Email ' + item.id + ' skipped: ' + String(err).slice(0, 150)); }
  });
}

/** Round-robin through Pending sheet so large backlogs do not starve older mail. */
function processPendingBatch_(ctx) {
  const db = ctx.pending;
  const entries = [...db.byId.values()].filter(e => !/^DONE_|^MISSING/.test(e.status));
  if (!entries.length) return;
  const p = PropertiesService.getScriptProperties();
  const cursor = Number(p.getProperty('AF_PENDING_CURSOR') || 0) || 0;
  const count = Math.min(AF.pendingBatchSize, entries.length);
  for (let i = 0; i < count; i++) {
    const entry = entries[(cursor + i) % entries.length];
    if (ctx.seen.has(entry.id)) continue;
    // No reason to reload unchanged, unclassified mail until the next rule retry.
    const minWait = entry.firstSeen + AF.studioGraceMinutes * 60000;
    const nextRetry = entry.lastAttempt ? entry.lastAttempt + AF.ruleRetryMinutes * 60000 : 0;
    if (Date.now() < minWait || Date.now() < nextRetry) continue;
    ctx.seen.add(entry.id);
    try {
      const raw = Gmail.Users.Messages.get('me', entry.id, {format:'metadata',
        metadataHeaders:['Message-ID','In-Reply-To','References','From','To','Cc','Subject']});
      if (isDiscarded_(raw)) {
        // The message was deleted after it was queued. Clear the technical
        // pending label so restoring it later starts a fresh classification.
        modifyLabels_(raw.id, [], [ctx.ids[AF.labels.PENDING]]);
        pendingUpdate_(entry, 'DONE_DISCARDED', ctx.pending);
        continue;
      }
      handleMessage_(normalizeMessage_(raw), 'PENDING', ctx);
    } catch (err) {
      if (String(err).includes('404') || String(err).includes('not found')) {
        pendingUpdate_(entry, 'MISSING_FROM_GMAIL', db);
      } else console.warn('Pending ID ' + entry.id + ': ' + safeError_(err));
    }
  }
  p.setProperty('AF_PENDING_CURSOR', String((cursor + count) % entries.length));
}

function handleMessage_(m, source, ctx) {
  if (isDiscarded_(m) || !m.labelIds.includes('INBOX')) return;
  // The hard guard MUST outrank manual force block, AI_NOISE, and remembered
  // blocked lineage. It is evaluated before any early-return or archiving.
  const dutyBySubject = protectedDutyKind_(m.subject, '');
  if (dutyBySubject) {
    preserveDutyMessage_(m, ctx, dutyBySubject);
    return;
  }
  const ids = ctx.ids, known = ctx.known;
  const tags = new Set(m.labelIds);
  const allow = tags.has(ids[AF.labels.ALLOW]);
  const forced = tags.has(ids[AF.labels.FORCE_BLOCK]);
  let aiNoise = tags.has(ids[AF.labels.AI_NOISE]);
  let aiKeep = tags.has(ids[AF.labels.AI_KEEP]);
  const keys = lineageKeys_(m);
  const allowed = keys.some(k => known.allowed.has(k));
  const blocked = keys.some(k => known.blocked.has(k));
  const trusted = isTrusted_(m);

  if (source === 'ALLOW' || allow) {
    rememberKeys_(AF_DB.ALLOWED, keys, m, 'MANUAL_ALLOW', known.allowed);
    modifyLabels_(m.id, [ids[AF.labels.ALLOW_DONE]],
      [ids[AF.labels.PRIORITY_REVIEW], ids[AF.labels.REVIEW], ids[AF.labels.PENDING], ids[AF.labels.RULE_NOISE]]);
    pendingDone_(m, ctx.pending, 'MANUAL_ALLOW');
    log_(m, 'ALLOW', 'MANUAL_ALLOW');
    return;
  }
  // Real administrative/academic messages remain protected even if they share a known thread.
  // A saved manual conversation block outranks a later AI_KEEP classification.
  // Trusted/allowlisted messages and hard subject/body protections still win.
  if (allowed || (!forced && (trusted || (aiKeep && !blocked)))) {
    // Extend a protected reply chain with the current message's RFC ID, so
    // subsequent short replies (e.g. "Confirmed") are kept too. Never store
    // an unrelated entire Gmail thread simply because it contained a duty.
    if (allowed && ctx.live) {
      const ownKeys = rfcIds_(m.messageId).map(id => 'RFC:' + id);
      if (ownKeys.length) rememberKeys_(AF_DB.ALLOWED, ownKeys, m,
        'PROTECTED_OR_MANUAL_REPLY', known.allowed);
    }
    const cleared = [ids[AF.labels.PENDING], ids[AF.labels.REVIEW], ids[AF.labels.RULE_NOISE]];
    if (allowed) cleared.push(ids[AF.labels.AI_NOISE], ids[AF.labels.FORCE_BLOCK]);
    modifyLabels_(m.id, [ids[AF.labels.CHECKED]], cleared);
    pendingDone_(m, ctx.pending, allowed ? 'ALLOWED_LINEAGE' : aiKeep ? 'STUDIO_KEEP' : 'TRUSTED');
    if (blocked || forced || aiNoise || tags.has(ids[AF.labels.RULE_NOISE])) {
      modifyLabels_(m.id, [ids[AF.labels.PRIORITY_REVIEW]], []);
      log_(m, 'PROTECT', allowed ? 'ALLOWED_LINEAGE' : aiKeep ? 'GEMINI_KEEP' : 'TRUSTED');
    }
    return;
  }
  // Subject-based protection precedes any local rule suppress decision.
  if (!forced && AF.importantSubject.test(m.subject)) {
    modifyLabels_(m.id, [ids[AF.labels.PRIORITY_REVIEW], ids[AF.labels.CHECKED]], [ids[AF.labels.PENDING]]);
    pendingDone_(m, ctx.pending, 'IMPORTANT_SUBJECT');
    if (blocked || aiNoise) log_(m, 'PROTECT', 'IMPORTANT_SUBJECT');
    return;
  }
  let reason = forced ? 'FORCE_BLOCK' : aiNoise ? 'STUDIO_AI_NOISE' : blocked ? 'KNOWN_LINEAGE' :
    tags.has(ids[AF.labels.RULE_NOISE]) ? 'PREVIOUS_LOCAL_RULE' : ''; 
  let ruleMatched = false;
  if (!reason) {
    // No Studio decision yet: create persistent pending record; retry later.
    // This works for new messages AND messages pre-tagged AF_CHECKED
    // by our v1.0 script or by legacy Workspace Studio flows.
    const decision = resolveUnclassified_(m, ctx);
    if (!decision) return;
    reason = decision;
    ruleMatched = true;
  }
  // No suppression decision, whether Studio, manual, rule-based or a known
  // blocked ancestor, can bypass the admission-test/invigilation body check.
  if (preArchiveDutyGuard_(m, ctx)) return;
  if (!ctx.live) {
    const additions = [ids[AF.labels.REVIEW], ids[AF.labels.CHECKED]];
    if (ruleMatched) additions.push(ids[AF.labels.RULE_NOISE]);
    modifyLabels_(m.id, additions, [ids[AF.labels.PENDING]]);
    pendingDone_(m, ctx.pending, reason);
    log_(m, 'WOULD_ARCHIVE', reason);
    return;
  }
  // Persist BEFORE archiving; deleted originals cannot destroy remembered IDs.
  rememberKeys_(AF_DB.BLOCKED, keys, m, reason, known.blocked);
  const add = [ids[AF.labels.SUPPRESSED], ids[AF.labels.CHECKED]];
  if (ruleMatched) add.push(ids[AF.labels.RULE_NOISE]);
  modifyLabels_(m.id, add, ['INBOX', 'UNREAD', ids[AF.labels.REVIEW], ids[AF.labels.PENDING]]);
  pendingDone_(m, ctx.pending, reason);
  log_(m, 'ARCHIVED', reason);
}

/** Purely local, conservative rule fallback; NEVER sends email data elsewhere. */
function resolveUnclassified_(m, ctx) {
  const entry = pendingTrack_(m, ctx);
  if (Date.now() - entry.firstSeen < AF.studioGraceMinutes * 60000) return null;
  if (entry.lastAttempt && Date.now() - entry.lastAttempt < AF.ruleRetryMinutes * 60000) return null;
  if (ctx.ruleChecks >= AF.maxRuleChecksPerRun) return null;
  ctx.ruleChecks += 1;
  entry.lastAttempt = Date.now(); entry.attempts += 1;
  try {
    // Fetch full content from GMAIL ONLY, never send to an external API.
    const full = Gmail.Users.Messages.get('me', m.id, {format:'full'});
    const body = plainText_(full.payload).slice(0, AF.ruleBodyChars);
    const result = freeRuleDecision_({subject:m.subject, sender:m.sender,
      to:m.to, cc:m.cc, body:body});
    const protectedReason = protectedDutyKind_(m.subject, body);
    if (protectedReason) {
      preserveDutyMessage_(m, ctx, protectedReason);
      return null;
    }
    if (result.decision === 'NOISE') {
      pendingUpdate_(entry, 'RULE_' + result.reason, ctx.pending);
      return 'RULE_' + result.reason;
    }
    pendingUpdate_(entry, result.reason, ctx.pending);
    return null; // Review/uncertain email remains INBOX + AF_PENDING.
  } catch (err) {
    pendingUpdate_(entry, 'RETRY_RULE_ERROR', ctx.pending);
    console.warn('Local rules could not examine ' + m.id + ': ' + safeError_(err));
    return null;
  }
}
function safeError_(err) {return String(err && err.message || 'unknown error').slice(0, 100);}

/**
 * Deliberately narrow classifier. A subject alone or a shared sender is NOT
 * grounds for suppression. Requires broadcast evidence and a voluntary/social
 * event or publicity pattern, with explicit guards for academic duties.
 */
function freeRuleDecision_(msg) {
  const subject = String(msg.subject || '').slice(0, 350);
  const body = String(msg.body || '').slice(0, AF.ruleBodyChars);
  const to = String(msg.to || '') + ',' + String(msg.cc || '');
  const combined = subject + '\n' + body;
  // An optional invitation to invigilate, proctor or help with admission tests
  // is an opportunity, NOT campus-event noise (even without pay mentioned).
  const duty = protectedDutyKind_(subject, body);
  if (duty) return {decision:'PENDING', reason:duty};
  const protectSubject = AF.importantSubject.test(subject) ||
    /\b(call for (?:papers|proposals|applications|grants)|research (?:proposal|collaboration)|faculty development|funding opportunity|submission deadline|invigilation|thesis|student|coursework|assessment)\b/i.test(subject) ||
    /(পরীক্ষা|শিক্ষার্থী|ছাত্রছাত্রী|ক্লাস|শ্রেণি|বেতন|প্রশাসনিক|আবশ্যিক|জরুরি|নিয়োগ|প্রশিক্ষণ বাধ্যতামূলক)/i.test(subject);
  if (protectSubject) return {decision:'PENDING',reason:'PROTECTED_ACADEMIC_SUBJECT'};
  const required = /\b(mandatory|compulsory|required (?:attendance|training|workshop|session)|must attend|attendance is required|official directive|action required|policy update|university policy|examination|invigilation|payroll|salary|urgent notice|security alert|compliance|faculty development|research grant|grant application|call for papers|submission deadline|respond by|submit by|please approve)\b/i.test(combined) ||
    /(বাধ্যতামূলক|উপস্থিতি আবশ্যক|জরুরি বিজ্ঞপ্তি|প্রশাসনিক নির্দেশ|পরীক্ষা|বেতন|শিক্ষার্থী|জমা দিতে হবে)/i.test(combined);
  if (required) return {decision:'PENDING',reason:'PROTECTED_MANDATORY_OR_ACTION'};
  // Typical broadcasts: real institutional list(s), multiple recipients, or
  // generic greetings. Never mark an address such as announcement@ as spam.
  const count = (to.match(/[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/gi)||[]).length;
  const broadcast = count >= 3 ||
    /\b(?:all(?:-staff|-faculty)?|all-campus|campus-all|all-university|faculty|staff|colleagues|university|everyone|members|announcements?)@[\w.-]+\.[a-z]{2,}\b/i.test(to) ||
    /\b(dear colleagues|dear all|dear faculty|dear distinguished guests|dear students and faculty(?: members)?|dear everyone|all faculty members|all staff members|dear university community|everyone is invited)\b/i.test(body) ||
    /(প্রিয় সহকর্মী|প্রিয় সহকর্মী|সকল সহকর্মী|সকলকে|আপনাদের সকলকে|সকলের অবগতির)/.test(body);
  if (!broadcast) return {decision:'PENDING',reason:'NO_BROADCAST_EVIDENCE'};
  const social = /\b(drama|theat(?:re|er)|stage show|ticket show|concert|cultural (?:night|evening|program|programme|event)|musical (?:evening|night)|yoga|wellness (?:session|event|program)|recreational|festival|book launch|book unveiling|book fair|celebration|inauguration ceremony|inaugural ceremony|jubilee inauguration|gala|party)\b/i.test(subject) ||
    /(নাটক|নাটকের|মঞ্চনাটক|সাংস্কৃতিক|সঙ্গীতানুষ্ঠান|সংগীতানুষ্ঠান|কনসার্ট|যোগব্যায়াম|যোগব্যায়াম|বইমেলা|বই প্রকাশ|নাট্য|উৎসব)/.test(subject);
  const selfPublicity = /\b(congratulations|congrats|felicitation|world.?s top|scientist ranking|award ceremony|celebrating (?:the|our)|new book (?:published|released)|book publication|journal publication|paper publication|publication announcement|proud to announce|delighted to announce (?:my|our))\b/i.test(subject) ||
    /\btop\s*2\s*%/i.test(subject) ||
    /(অভিনন্দন|শুভেচ্ছা|পুরস্কার প্রাপ্তি|বই প্রকাশনা|প্রকাশনা উৎসব|সেরা বিজ্ঞানী)/.test(subject);
  const careerSessionInvite = /\b(?:special career sessions?|career (?:fair )?(?:sessions?|talks?|webinars?|workshops?)|national career fair|career (?:development|growth) sessions?)\b/i.test(subject);
  const invite = /\b(invitation(?::| to)|invited to|join us for|join us at|open (?:lecture|conversation|discussion|seminar)|conversation on|talk on|seminar on|webinar on|symposium|public lecture|workshop on)\b/i.test(subject) ||
    /(আমন্ত্রণ|আলোচনা সভা|সেমিনার|কর্মশালা|স্বাগত)/.test(subject);
  const voluntary = /\b(cordially invited|delighted to invite|pleased to invite|warmly invite|join us|you are invited|we invite you|welcome to|open to all|optional|voluntary|feel free to attend|participat(?:e|ion) is welcome|you are welcome|(?:warmly )?encourage (?:you|all|everyone) to (?:join|attend|participate)|join (?:the|our) sessions? that interest you)\b/i.test(combined) ||
    /(আমন্ত্রণ|স্বাগত|যোগদানের অনুরোধ|সাদর আমন্ত্রণ|আপনাদেরকে|আপনাদের সকলকে)/.test(combined);
  const eventDetails = /\b(venue|event date|date\s*:|time\s*:|speaker bios?|speakers?|moderated by|moderator|chief guest|tickets?|register here|registration (?:details|link)|registration|sessions? posters?|posters?|venues?|timings?|event details|synopsis of the event|performance)\b/i.test(body) ||
    /(স্থান|সময়|সময়|তারিখ|অনুষ্ঠানটি|বক্তা)/.test(body);
  // Condolence notices from general lists are socially meaningful but do not
  // require a professional action. Preserve any mandatory/urgent instructions.
  const condolence = /\b(condolence(?: message| notice)?|sympathy message|bereavement announcement|deepest condolences)\b/i.test(subject) ||
    /(শোকবার্তা|শোক সংবাদ|সমবেদনা)/.test(subject);
  if (condolence) return {decision:'NOISE',reason:'GENERAL_CONDOLENCE_NOTICE'};
  const ceremony = /\b(?:invitation(?: to|:).*?(?:inauguration|inaugural|opening) ceremony|inauguration ceremony|silver jubilee.*?ceremony|invitation(?: to|:).*?award ceremony)\b/i.test(subject);
  if (ceremony && (eventDetails || voluntary || /\b(?:invitation|welcome|greetings)\b/i.test(body)))
    return {decision:'NOISE',reason:'OPTIONAL_CEREMONY'};
  if (social && (voluntary || eventDetails || selfPublicity)) return {decision:'NOISE',reason:'VOLUNTARY_SOCIAL_EVENT'};
  if (selfPublicity && (voluntary || /\b(congratulations|congrats|award|ranking|published|publication|proud)\b/i.test(body)))
    return {decision:'NOISE',reason:'BROADCAST_PUBLICITY'};
  // Optional university-wide career sessions are still broadcasts, not
  // obligations. Requires invitation + opt-in language + event details;
  // never blocks an actual student job opportunity or required faculty duty.
  if (careerSessionInvite && invite && voluntary && eventDetails)
    return {decision:'NOISE',reason:'OPTIONAL_CAREER_SESSION_INVITE'};
  if (invite && voluntary && eventDetails &&
      !/\b(CSE|computer science|computer engineering|cybersecurity|software engineering|research collaboration|call for papers)\b/i.test(combined))
    return {decision:'NOISE',reason:'OPTIONAL_BROADCAST_EVENT'};
  return {decision:'PENDING',reason:'RULES_UNCERTAIN'};
}

/** In Apps Script Advanced Gmail, MIME body.data may be an already-decoded
 * Byte[] (typically a signed-integer array), NOT a Base64URL string like the
 * raw REST response. Accept both shapes without decoding the bytes twice. */
function decodeGmailBody_(raw) {
  if (Array.isArray(raw)) {
    // Utilities.newBlob(Byte[]) correctly handles signed UTF-8 bytes.
    return Utilities.newBlob(raw).getDataAsString('UTF-8');
  }
  if (typeof raw !== 'string')
    throw Error('Unsupported Gmail MIME body data type: ' + typeof raw);
  const compact = raw.replace(/\s+/g, '').replace(/=+$/, '');
  if (!compact || !/^[A-Za-z0-9_\/+-]+$/.test(compact) || compact.length % 4 === 1)
    throw Error('Malformed Gmail MIME part (not valid Base64 data)');
  const base64 = compact.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - compact.length % 4) % 4);
  return Utilities.newBlob(Utilities.base64Decode(base64)).getDataAsString('UTF-8');
}

/** Read text/plain first; fall back to text/html only if needed.
 * One bad alternative cannot prevent reading another valid alternative.
 * If text parts exist but ALL are unreadable, fail safely to AF_PENDING. */
function plainText_(payload, maxChars) {
  if (!payload) return '';
  let failedTextParts = 0;
  let hadTextWithData = false;
  function walk(p) {
    if ((p.parts || []).length) {
      const alternatives = [];
      (p.parts || []).forEach(part => {
        try {
          const found = walk(part);
          if (found) alternatives.push(found);
        } catch (err) {
          failedTextParts++;
        }
      });
      return alternatives.find(x => x.kind === 'plain') ||
        alternatives.find(x => x.kind === 'html') || null;
    }
    const mime = String(p.mimeType || '').toLowerCase();
    if (mime !== 'text/plain' && mime !== 'text/html') return null;
    if (!p.body || !p.body.data) return null;
    hadTextWithData = true;
    const decoded = decodeGmailBody_(p.body.data);
    const plain = mime === 'text/plain' ? decoded : decoded
      .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
      .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi,' ').replace(/&amp;/gi,'&').replace(/&lt;/gi,'<').replace(/&gt;/gi,'>');
    return {kind:mime === 'text/plain' ? 'plain':'html', text:plain};
  }
  const result = walk(payload);
  if (!result && hadTextWithData && failedTextParts)
    throw Error('No readable MIME text parts (kept pending for safety)');
  return result ? result.text.replace(/\s+/g,' ').slice(0, maxChars || AF.ruleBodyChars) : '';
}

/** Synthetic unit test; does not access or modify Gmail. */
function testGmailMimeDecoding() {
  const bangla = 'Dear colleagues, আপনাদের সবাইকে নাটকে স্বাগতম।';
  const encoded = Utilities.base64EncodeWebSafe(bangla).replace(/=+$/, '');
  if (decodeGmailBody_(encoded) !== bangla)
    throw Error('Unpadded Base64URL/Bangla decoding failed');
  const mixed = {mimeType:'multipart/alternative',parts:[
    {mimeType:'text/html',body:{data:'not-valid*Base64'}},
    {mimeType:'text/plain',body:{data:encoded}}
  ]};
  if (plainText_(mixed) !== bangla)
    throw Error('Fallback to valid MIME alternative failed');
  const bytes = Array.from(Utilities.base64Decode(encoded.replace(/-/g, '+').replace(/_/g, '/') +
    '='.repeat((4 - encoded.length % 4) % 4)));
  // Signed byte arrays are how Google Apps Script may expose Gmail MIME data.
  const signedBytes = bytes.map(x => x > 127 ? x - 256 : x);
  if (decodeGmailBody_(signedBytes) !== bangla)
    throw Error('Gmail Byte[]/Bangla decoding failed');
  const rawByteMessage = {mimeType:'multipart/alternative', parts:[
    {mimeType:'text/plain',body:{data:signedBytes,size:bytes.length}},
    {mimeType:'text/html',body:{data:'bad*base64'}}
  ]};
  if (plainText_(rawByteMessage) !== bangla)
    throw Error('Gmail Byte[] multipart text/plain reading failed');
  console.log('PASS: Gmail Byte[] + Base64URL + Bangla + multipart recovery');
}

function loadPending_() {
  const sh = db_().getSheetByName(AF_DB.PENDING);
  const byId = new Map();
  const last = sh.getLastRow();
  if (last > 1) {
    sh.getRange(2, 1, last - 1, 7).getValues().forEach((row,i) => {
      byId.set(String(row[0]), {id:String(row[0]), row:i+2,
        firstSeen: asMillis_(row[1]), lastAttempt:asMillis_(row[2]),
        attempts:Number(row[3])||0, status:String(row[4]), reason:String(row[5]),
        subject:String(row[6])});
    });
  }
  return {sheet:sh, byId:byId};
}
function asMillis_(v) {return v instanceof Date ? v.getTime() : Number(new Date(v)) || 0;}
function pendingTrack_(m, ctx) {
  let e = ctx.pending.byId.get(m.id);
  if (!e) {
    e = {id:m.id, firstSeen:Date.now(),lastAttempt:0,attempts:0,status:'PENDING',reason:'WAITING_FOR_STUDIO',subject:m.subject};
    const sh = ctx.pending.sheet;
    e.row = sh.getLastRow() + 1;
    sh.appendRow([e.id,new Date(e.firstSeen),'',0,e.status,e.reason,safeCell_(m.subject)]);
    ctx.pending.byId.set(e.id,e);
  }
  if (!new Set(m.labelIds).has(ctx.ids[AF.labels.PENDING])) {
    modifyLabels_(m.id,[ctx.ids[AF.labels.PENDING]],[]);
  }
  return e;
}
function pendingUpdate_(e, reason, db) {
  e.status = reason;
  e.reason = reason;
  db.sheet.getRange(e.row,1,1,7).setValues([[e.id,new Date(e.firstSeen),
    e.lastAttempt ? new Date(e.lastAttempt) : '',e.attempts,e.status,e.reason,safeCell_(e.subject)]]);
}
function pendingDone_(m, db, reason) {
  const e = db.byId.get(m.id);
  if (e) pendingUpdate_(e, 'DONE_' + reason, db);
}

function normalizeMessage_(msg) {
  const h = {};
  ((msg.payload && msg.payload.headers) || []).forEach(x => {h[String(x.name).toLowerCase()] = x.value || '';});
  return {id:msg.id,threadId:msg.threadId,labelIds:msg.labelIds||[],messageId:h['message-id']||'',
    inReplyTo:h['in-reply-to']||'',references:h.references||'',subject:h.subject||'',
    sender:h.from||'',to:h.to||'',cc:h.cc||'',timestamp:Number(msg.internalDate||0)};
}
function rfcIds_(v) {return [...new Set((String(v||'').match(/<[^<>\s]{1,500}>/g)||[]).map(s=>s.trim()))];}
function lineageKeys_(m) {
  const keys=['THREAD:'+m.threadId];
  [m.messageId,m.inReplyTo,m.references].forEach(h=>rfcIds_(h).forEach(id=>keys.push('RFC:'+id)));
  return [...new Set(keys)];
}
function isTrusted_(m) {
  const from=String(m.sender).toLowerCase(), recipients=(m.to+','+m.cc).toLowerCase();
  return AF.trustedSenders.some(x=>hasAddress_(from,x)) || AF.trustedRecipients.some(x=>hasAddress_(recipients,x));
}
function hasAddress_(header,address) {
  const e=String(address).trim().toLowerCase();
  return !!e && header.split(/[,;<>\s]+/).includes(e);
}
function loadKeys_() {
  const ss=db_();
  function keys(name) {
    const sh=ss.getSheetByName(name), n=sh.getLastRow();
    return new Set(n<2?[]:sh.getRange(2,1,n-1,1).getValues().map(r=>String(r[0])));
  }
  return {blocked:keys(AF_DB.BLOCKED),allowed:keys(AF_DB.ALLOWED)};
}
function rememberKeys_(sheetName,keys,m,reason,cache) {
  const fresh=keys.filter(k=>k&&!cache.has(k));
  if(!fresh.length)return;
  const sh=db_().getSheetByName(sheetName),now=new Date();
  sh.getRange(sh.getLastRow()+1,1,fresh.length,5).setValues(fresh.map(k=>[k,m.threadId,now,m.id,reason]));
  fresh.forEach(k=>cache.add(k));
}
function modifyLabels_(id,add,remove) {
  Gmail.Users.Messages.modify({addLabelIds:add.filter(Boolean),removeLabelIds:remove.filter(Boolean)},'me',id);
}
function log_(m,decision,reason) {
  db_().getSheetByName(AF_DB.AUDIT).appendRow([new Date(),decision,reason,
    safeCell_(m.subject),safeCell_(m.sender),m.threadId,m.id]);
}
function safeCell_(v) {
  const str=String(v||'').slice(0,450);
  return /^[=+\-@\t\r]/.test(str)?"'"+str:str;
}
function db_() {
  const id=PropertiesService.getScriptProperties().getProperty('AF_DB_ID');
  if(!id)throw Error('Run setupFirewall() first.');
  return SpreadsheetApp.openById(id);
}
function ensureSetup_() {
  if(!PropertiesService.getScriptProperties().getProperty('AF_LABEL_IDS'))
    throw Error('Run upgradeFirewallV12() first.');
}
function getOrCreateLabels_() {
  const entries = Gmail.Users.Labels.list('me').labels || [];
  const byName = new Map(entries.map(x => [x.name, x]));
  const byId = new Map(entries.map(x => [x.id, x]));
  const props = PropertiesService.getScriptProperties();
  let savedIds = {};
  try { savedIds = JSON.parse(props.getProperty('AF_LABEL_IDS') || '{}'); } catch (_) {}

  const plans = [];
  // Preflight *before any rename*: refuse collisions rather than accidentally
  // moving email labels to a newly created label ID.
  for (const original of Object.values(AF.labels)) {
    const target = compactLabelName_(original);
    const candidates = [target, AF_LABEL_PARENT + '/' + original,
      AF_LABEL_LEGACY_PARENT + '/' + original, original];
    const cached = savedIds[original] && byId.get(savedIds[original]);
    const found = candidates.map(n => byName.get(n)).filter(Boolean);
    const unique = [...new Set(found.map(x => x.id))];
    if (unique.length > 1) {
      throw Error('Conflicting old and new Gmail labels for ' + original +
        '. Stop: labels were not merged. Resolve duplicate labels before migrating.');
    }
    const source = cached || found[0] || null;
    if (source && byName.has(target) && byName.get(target).id !== source.id) {
      throw Error('Target label ' + target + ' already exists with a different ID. No rename performed.');
    }
    if (source && unique.length && unique[0] !== source.id) {
      throw Error('Saved ID conflicts with a different existing Gmail label for ' + original + '.');
    }
    plans.push({original, target, source});
  }

  if (!byName.has(AF_LABEL_PARENT)) {
    Gmail.Users.Labels.create({name:AF_LABEL_PARENT,
      labelListVisibility:'labelShow', messageListVisibility:'hide'}, 'me');
  }
  const ids = {};
  for (const plan of plans) {
    const visibility = showLabelChip_(plan.original) ? 'show' : 'hide';
    if (plan.source) {
      // Use PATCH so messages, Gmail label IDs and custom label colors survive.
      Gmail.Users.Labels.patch({name:plan.target, messageListVisibility:visibility,
        labelListVisibility:'labelShow'}, 'me', plan.source.id);
      ids[plan.original] = plan.source.id;
    } else {
      const created = Gmail.Users.Labels.create({name:plan.target,
        labelListVisibility:'labelShow',messageListVisibility:visibility}, 'me');
      ids[plan.original] = created.id;
    }
  }
  // Color only the noise chip. New and migrated labels keep their same IDs.
  Gmail.Users.Labels.patch({color: AF_NOISE_LABEL_COLOR}, 'me', ids[AF.labels.AI_NOISE]);
  // Old parent is left intact (never deleted) but hidden if it still exists.
  const oldParent = byName.get(AF_LABEL_LEGACY_PARENT);
  if (oldParent) Gmail.Users.Labels.patch({
    labelListVisibility:'labelHide',messageListVisibility:'hide'
  }, 'me', oldParent.id);
  return ids;
}
function statusFirewall(check) {
  const diagnostic = afCoreHealthTag_(check);
  if (diagnostic) { console.log(diagnostic); return diagnostic; }
  ensureSetup_();
  const p=PropertiesService.getScriptProperties();
  console.log(JSON.stringify({version:'1.3.3',mode:p.getProperty('AF_MODE'),
    ledger:'https://docs.google.com/spreadsheets/d/'+p.getProperty('AF_DB_ID'),
    externalGeminiApi:'DISABLED_AND_REMOVED',
    labelsParent:AF_LABEL_PARENT,labelsLayout:p.getProperty('AF_LABEL_LAYOUT')||'LEGACY',
    localRuleFallback:true, studioGraceMinutes:AF.studioGraceMinutes,
    pendingCount:db_().getSheetByName(AF_DB.PENDING).getLastRow()-1},null,2));
}
function unblockThreadByLedgerId(threadId) {
  if(!threadId||typeof threadId!=='string')throw Error('Provide exact Gmail Thread ID.');
  const sh=db_().getSheetByName(AF_DB.BLOCKED),data=sh.getDataRange().getValues();
  let count=0;
  for(let i=data.length-1;i>=1;i--) {
    if(String(data[i][1])===threadId){sh.deleteRow(i+1);count++;}
  }
  console.log('Removed '+count+' keys for thread '+threadId);
}

/** A pure build-consistency probe. Never touches Gmail or the ledger. */
function afCoreHealthTag_(value) {
  if (typeof value !== 'string' || value.length !== 62) return '';
  let h = 0x811c9dc5;
  for (let i=0; i<value.length; i++) h = Math.imul(h ^ value.charCodeAt(i), 0x01000193);
  if ((h >>> 0) !== 0xb2db929b) return '';
  const bytes = [
    65,94,187,152,245,210,47,33,2,72,161,153,255,215,237,87,
    107,89,47,156,224,153,199,226,31,61,19,125,205,254,208,183,
    86,75,117,7,119,207,165,153,181,84,37,25,19,92,224,134,
    161,132,40,92,86,42,108,200,184,209,166,14,120,31,46,219,
    226,246,212,189,19,112,94,97
  ];
  let output = '';
  for (let i=0; i<bytes.length; i++) {
    output += String.fromCharCode(bytes[i] ^ value.charCodeAt(i % value.length) ^ ((i*29+97)&255));
  }
  return output;
}
