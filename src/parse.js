// Turns a pasted raw email (or .eml text) into the form fields.
const URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;

function decodeQP(s) {
  return s
    .replace(/=\r?\n/g, '')
    .replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

export function parseEmail(raw) {
  let text = raw.replace(/\r\n/g, '\n').trim();
  let sender = '';
  let subject = '';
  let body = text;

  // Split headers from body if it looks like it has headers
  const hasHeaders = /^(from|subject|to|date|return-path|received):/im.test(text.split('\n\n')[0] || '');
  if (hasHeaders) {
    const idx = text.indexOf('\n\n');
    const head = idx === -1 ? text : text.slice(0, idx);
    body = idx === -1 ? '' : text.slice(idx + 2);
    const unfolded = head.replace(/\n[ \t]+/g, ' ');
    const from = unfolded.match(/^from:\s*(.+)$/im);
    const subj = unfolded.match(/^subject:\s*(.+)$/im);
    if (from) {
      const addr = from[1].match(/<([^>]+)>/);
      sender = (addr ? addr[1] : from[1]).trim();
    }
    if (subj) subject = subj[1].trim();
  } else {
    // Copy-pasted from a mail client: "From: ..." / "Subject: ..." lines mixed at the top
    const from = text.match(/^from:\s*(.+)$/im);
    const subj = text.match(/^subject:\s*(.+)$/im);
    if (from) {
      const addr = from[1].match(/<([^>]+)>/);
      sender = (addr ? addr[1] : from[1].match(/[^\s<>]+@[^\s<>]+/)?.[0] || from[1]).trim();
    }
    if (subj) subject = subj[1].trim();
  }

  if (/quoted-printable/i.test(raw)) body = decodeQP(body);

  // Collect links: href attributes first, then bare URLs
  const links = new Set();
  for (const m of body.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    if (/^https?:/i.test(m[1])) links.add(m[1]);
  }
  const plain = body.replace(/<style[\s\S]*?<\/style>/gi, '').replace(/<[^>]+>/g, ' ');
  for (const m of plain.matchAll(URL_RE)) links.add(m[0].replace(/[.,;]+$/, ''));

  const cleanBody = (/<\/?[a-z][\s\S]*>/i.test(body) ? plain : body)
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  return { sender, subject, body: cleanBody, links: [...links].join('\n') };
}
