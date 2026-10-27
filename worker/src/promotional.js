// Metadata-only rules. Cloudflare EmailMessage supplies envelope addresses and
// headers here; this Worker does not read the body or attachments. A single
// keyword or mailing-list header never blocks a message. Unclear or mixed
// messages are delivered, so these rules will miss some promotions.

const SUBJECT_LIMIT = 998;
const HEADER_LIMIT = 512;
const PROMOTIONAL_SUBJECT = [
  /\b(?:sale|clearance)\b/,
  /\bdiscount\b|\b\d{1,2}%\s*off\b|\bsave\s+\d{1,2}%/,
  /\b(?:coupon|promo(?:tional)?\s+code|voucher)\b/,
  /\b(?:limited[ -]time|special|exclusive)\s+(?:offer|deal)\b/,
  /\b(?:newsletter|marketing campaign|product launch)\b/,
  /\b(?:buy one get one|flash deal)\b/,
];
const TRANSACTIONAL_SUBJECT = [
  /\bpassword\s+(?:reset|change|changed)\b/,
  /\b(?:security|login|sign[ -]?in)\s+(?:alert|code|verification|attempt|notification)\b/,
  /\b(?:verification|one[ -]?time|otp)\s+code\b/,
  /\b(?:order\s+(?:confirmation|confirmed|shipped|delivered)|shipping\s+(?:update|confirmation|notification))\b/,
  /\b(?:payment\s+(?:failed|failure|declined)|card\s+declined)\b/,
  /\b(?:receipt|invoice)\s+(?:for|number|#\d|is\s+ready)\b/,
  /\b(?:your\s+)?(?:receipt|invoice)\b.*\b(?:order|payment|purchase|transaction)\b/,
];
const PROMO_ID = /\b(?:newsletter|marketing|promotions?|offers?|deals?)\b/;
const PROMO_SENDER = /\b(?:newsletter|marketing|promotions?|offers?|deals?)\b|(?:^|[<\s])(?:newsletter|marketing|promotions?|offers?|deals?)[^@\s]*@/;

function normalized(value, limit) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string" || value.length > limit) return null;
  return value.replace(/[\x00-\x1f\x7f]/g, " ").replace(/\s+/g, " ").trim().toLowerCase();
}

/** Return { outcome, reason } with only safe, fixed reason codes. */
export function classifyPromotionalMetadata(input) {
  try {
    if (!input || typeof input !== "object") return { outcome: "uncertain", reason: "malformed" };
    const subject = normalized(input.subject, SUBJECT_LIMIT);
    const listId = normalized(input.listId, HEADER_LIMIT);
    const listUnsubscribe = normalized(input.listUnsubscribe, HEADER_LIMIT);
    const from = normalized(input.from, HEADER_LIMIT);
    const replyTo = normalized(input.replyTo, HEADER_LIMIT);
    if ([subject, listId, listUnsubscribe, from, replyTo].includes(null)) {
      return { outcome: "uncertain", reason: "malformed" };
    }

    const transactional = TRANSACTIONAL_SUBJECT.some((pattern) => pattern.test(subject));
    const promoSubjectSignals = PROMOTIONAL_SUBJECT.filter((pattern) => pattern.test(subject)).length;
    const promotionalList = Boolean(listId && PROMO_ID.test(listId));
    const unsubscribe = Boolean(listUnsubscribe);
    const promotionalSender = PROMO_SENDER.test(from) || PROMO_SENDER.test(replyTo);

    // Important content wins over generic list headers; an explicit offer in
    // the same subject makes the message mixed and therefore deliverable.
    if (transactional) return promoSubjectSignals
      ? { outcome: "uncertain", reason: "mixed" }
      : { outcome: "transactional", reason: "important_subject" };

    const promotional = promoSubjectSignals >= 2
      || (promoSubjectSignals >= 1 && (promotionalList || unsubscribe || promotionalSender))
      || (promotionalList && unsubscribe && promotionalSender);
    return promotional
      ? { outcome: "promotional", reason: "promo_signals" }
      : { outcome: "uncertain", reason: "insufficient_evidence" };
  } catch {
    return { outcome: "uncertain", reason: "malformed" };
  }
}
