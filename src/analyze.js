// Rough "example.co.in" style base-domain extraction (no external library).
function baseDomain(host) {
  const parts = host.toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const last = parts[parts.length - 1];
  const second = parts[parts.length - 2];
  const shortSecond = ['co', 'com', 'org', 'net', 'ac', 'edu', 'gov'].includes(second);
  return (shortSecond && last.length === 2 ? parts.slice(-3) : parts.slice(-2)).join('.');
}

// Sites many different senders use, so they say nothing about who sent the email.
const SHARED_HOSTS = ['forms.gle', 'google.com', 'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'linkedin.com', 'youtube.com'];

// Pure analysis logic: no DOM, easy to test.
export function analyzeEmail({ sender, subject, body, links }, ml = null) {
  const redFlags = [];
  const warnings = [];
  const positives = [];
  let riskScore = 0;

  // Separate "financial scam" dimension (fake jobs/internships, advance fees).
  let financialScore = 0;
  let feeRequested = false;

  const linkArray = links.split('\n').map((l) => l.trim()).filter(Boolean);

  // Sender
  if (sender) {
    const s = sender.toLowerCase();
    const lookalikes = ['paypa1', 'g00gle', 'micr0soft', 'amaz0n', 'app1e', 'netf1ix'];
    if (lookalikes.some((d) => s.includes(d))) {
      redFlags.push({
        title: 'Lookalike Domain Detected',
        description: `The email address "${sender}" uses character substitution (e.g., "0" for "o", "1" for "l") commonly used in phishing.`,
      });
      riskScore += 25;
    }

    const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    if (freeProviders.some((p) => s.endsWith(p)) && body.toLowerCase().includes('bank')) {
      warnings.push({
        title: 'Free Email Provider',
        description: 'Legitimate businesses typically use their own domain for official communications.',
      });
      riskScore += 10;
    }

    const badTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
    if (badTLDs.some((tld) => s.endsWith(tld))) {
      warnings.push({
        title: 'Suspicious Domain Extension',
        description: 'The sender uses a domain extension commonly associated with spam and phishing.',
      });
      riskScore += 15;
    }
  }

  // Subject
  if (subject) {
    const urgent = ['urgent', 'immediate', 'action required', 'suspended', 'verify now', 'confirm immediately', 'expires today'];
    if (urgent.some((w) => subject.toLowerCase().includes(w))) {
      redFlags.push({
        title: 'Urgent Language in Subject',
        description: `Subject contains urgent/threatening language: "${subject}". Phishers use urgency to bypass critical thinking.`,
      });
      riskScore += 20;
    }
    if (/[A-Z]{5,}/.test(subject)) {
      warnings.push({
        title: 'Excessive Capitalization',
        description: 'Subject line contains excessive capital letters, a common spam tactic.',
      });
      riskScore += 10;
    }
  }

  // Body
  if (body) {
    const b = body.toLowerCase();

    // Whole-word matching, so "pin" does not match "spinning" or "opinion".
    const sensitive = [
      ['password', /\bpasswords?\b/],
      ['credit card', /\bcredit card\b/],
      ['social security', /\bsocial security\b/],
      ['ssn', /\bssn\b/],
      ['bank account', /\bbank account\b/],
      ['pin', /\bpin\b/],
      ['verification code', /\bverification code\b/],
    ];
    const foundSensitive = sensitive.filter(([, re]) => re.test(b)).map(([name]) => name);
    if (foundSensitive.length) {
      redFlags.push({
        title: 'Requests Sensitive Information',
        description: `Email asks for sensitive data: ${foundSensitive.join(', ')}. Legitimate companies never ask for this via email.`,
      });
      riskScore += 30;
    }

    const threats = ['suspend', 'close your account', 'legal action', 'locked', 'unauthorized', 'unusual activity'];
    const foundThreats = threats.filter((t) => b.includes(t));
    if (foundThreats.length) {
      warnings.push({
        title: 'Threatening Language',
        description: `Contains threatening phrases: ${foundThreats.join(', ')}. Used to create panic and force hasty decisions.`,
      });
      riskScore += 15;
    }

    const typos = ['recieve', 'accout', 'varify', 'updaate', 'confrm'];
    if (typos.some((t) => b.includes(t))) {
      warnings.push({
        title: 'Spelling Errors Detected',
        description: 'Email contains obvious spelling mistakes, indicating unprofessional origin.',
      });
      riskScore += 10;
    }

    const greetings = ['dear customer', 'dear user', 'dear member', 'valued customer', 'dear student', 'dear applicant', 'dear candidate'];
    if (greetings.some((g) => b.includes(g))) {
      warnings.push({
        title: 'Generic Greeting',
        description: 'Uses generic greeting instead of your name. Legitimate companies personalize communications.',
      });
      riskScore += 8;
    }

    // "won" used to match words like "wonderful" and "won't".
    if (/\byou(?:'ve| have)? won\b|\blottery\b|\bprize\b/.test(b)) {
      redFlags.push({
        title: 'Unsolicited Prize Claim',
        description: "Claims you won something you didn't enter. Classic phishing/scam tactic.",
      });
      riskScore += 25;
    }

    // ---- Financial scam signals (fake jobs/internships, advance-fee fraud) ----
    const feeRules = [
      /\b(registration|processing|application|enrol?lment|training|certification|security|verification|administrative|admin)\s+(fee|fees|charge|charges|deposit)\b/,
      /\b(pay|submit|transfer|deposit)\b[^.\n]{0,40}\b(fee|fees|charges?)\b/,
      /\brefundable\b[^.\n]{0,30}\b(fee|deposit|amount)\b/,
      /(?:₹|rs\.?|inr|\$|usd)\s?\d[\d,]*[^.\n]{0,40}\b(fee|deposit|registration)\b/,
    ];
    if (feeRules.some((re) => re.test(b))) {
      feeRequested = true;
      redFlags.push({
        title: 'Fee or Payment Requested',
        description:
          'The email asks you to pay a fee or deposit. Scam job and internship offers often charge "registration" or "processing" fees. Some real programs charge fees too, so verify the organisation through its official website or phone number before paying.',
      });
      riskScore += 30;
      financialScore += 50;
    }

    if (/\bstipend\b[^.\n]{0,80}\b(subject to|conditional|depends|depending|based on|performance|after)\b/.test(b)) {
      warnings.push({
        title: 'Conditional Stipend',
        description: 'Payment is described as conditional or dependent on something. Ask for the exact terms in writing.',
      });
      riskScore += 10;
      financialScore += 20;
    }

    if (/\bguaranteed\b[^.\n]{0,30}\b(job|placement|internship|selection|offer)\b|\bno interview\b|\bwithout (?:any )?interview\b|\bdirect(?:ly)? selected?\b/.test(b)) {
      warnings.push({
        title: 'Guaranteed Selection / No Interview',
        description: 'Promises a job or internship with no real selection process, which is uncommon for genuine offers.',
      });
      riskScore += 12;
      financialScore += 20;
    }

    if (/\b(whatsapp|telegram)\b/.test(b)) {
      warnings.push({
        title: 'Asks You to Move to Messaging App',
        description: 'Moving the conversation to WhatsApp or Telegram is common in scams, though many real organisations use them too.',
      });
      riskScore += 8;
      financialScore += 10;
    }

    // Fees are mentioned but no amount is given (only if no direct fee request was found).
    if (!feeRequested && /\b(program|programme|course|internship|training|enrol?lment|applicable)\s+fees?\b/.test(b)) {
      warnings.push({
        title: 'Mentions Fees Without Stating Them',
        description: 'The email refers to program fees but gives no amount or terms. Ask for the exact fee, what it covers, and the refund policy in writing before applying.',
      });
      riskScore += 12;
      financialScore += 25;
    }

    if (/\b(limited (?:seats|slots)|seats (?:are )?limited|only \d+ (?:seats|slots)|register (?:now|today|immediately)|last date)\b/.test(b)) {
      warnings.push({
        title: 'Pressure to Act Quickly',
        description: 'Limited seats or tight deadlines are used to rush you into paying before you check.',
      });
      riskScore += 8;
      financialScore += 10;
    }
  }

  // Links
  linkArray.forEach((link) => {
    const l = link.toLowerCase();

    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
      redFlags.push({
        title: 'Link Uses IP Address',
        description: `Link "${link}" uses an IP address instead of a domain name. Highly suspicious.`,
      });
      riskScore += 20;
    }

    if (['bit.ly', 'tinyurl', 'goo.gl', 't.co'].some((s) => l.includes(s))) {
      warnings.push({
        title: 'URL Shortener Used',
        description: 'Link uses a URL shortener, hiding the actual destination. Verify before clicking.',
      });
      riskScore += 12;
    }

    if (l.includes('@') || l.includes('%20')) {
      warnings.push({
        title: 'Suspicious URL Pattern',
        description: `Link "${link}" contains suspicious characters that may hide the true destination.`,
      });
      riskScore += 15;
    }

    if (l.startsWith('http://')) {
      warnings.push({
        title: 'Insecure Connection',
        description: 'Link uses HTTP instead of HTTPS, making it vulnerable to interception.',
      });
      riskScore += 10;
    }
  });

  // Sender vs link domains (weak signal: real senders sometimes use third-party sites)
  if (sender && sender.includes('@') && linkArray.length) {
    const senderDomain = baseDomain(sender.split('@').pop().trim());
    const freeMail = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const linkDomains = linkArray
      .map((l) => {
        try {
          return baseDomain(new URL(l).hostname);
        } catch {
          return null;
        }
      })
      .filter((d) => d && !SHARED_HOSTS.includes(d));
    if (!freeMail.includes(senderDomain) && linkDomains.length && !linkDomains.includes(senderDomain)) {
      warnings.push({
        title: "Sender Domain Doesn't Match the Links",
        description: `The email comes from ${senderDomain}, but its links point to ${[...new Set(linkDomains)].join(', ')}. This is common in scams, but real third-party senders do it too. Confirm the sender really represents that organisation.`,
      });
      riskScore += 12;
    }
  }

  // Positives
  if (sender && sender.includes('@') && !redFlags.length) {
    positives.push({ title: 'Valid Email Format', description: 'Sender email address follows standard format.' });
  }
  if (linkArray.length && linkArray.every((l) => l.startsWith('https://'))) {
    positives.push({ title: 'Secure Links', description: 'All links use HTTPS encryption.' });
  }
  if (body && !/password|credit card|ssn|social security/i.test(body)) {
    positives.push({ title: 'No Sensitive Data Requests', description: 'Email does not request sensitive personal information.' });
  }

  const rulesScore = Math.min(riskScore, 100);

  // Trained model signal (TF-IDF + logistic regression), blended with the rules
  let finalScore = rulesScore;
  let mlPercent = null;
  if (ml && ml.probability != null) {
    mlPercent = Math.round(ml.probability * 100);
    const words = ml.topWords.length ? ` Strongest words: ${ml.topWords.join(', ')}.` : '';
    if (ml.probability >= 0.85) {
      redFlags.push({
        title: 'Trained Model: Resembles Phishing/Spam',
        description: `The model rates this text ${mlPercent}% likely to be phishing or spam.${words}`,
      });
    } else if (ml.probability >= 0.7) {
      warnings.push({
        title: 'Trained Model: Somewhat Suspicious',
        description: `The model rates this text ${mlPercent}% likely to be phishing or spam.${words}`,
      });
    } else if (ml.probability < 0.2) {
      positives.push({
        title: 'Trained Model: Looks Normal',
        description: `The model rates this text only ${mlPercent}% likely to be phishing or spam.`,
      });
    }
    finalScore = Math.round(0.6 * rulesScore + 0.4 * mlPercent);
  }

  // A fee request should never be averaged away by a calm-sounding text score.
  if (feeRequested) finalScore = Math.max(finalScore, 55);

  return {
    riskScore: finalScore,
    rulesScore,
    mlPercent,
    financialScore: Math.min(financialScore, 100),
    redFlags,
    warnings,
    positives,
  };
}

export const EXAMPLE = {
  sender: 'security@paypa1-support.tk',
  subject: 'URGENT: Your Account Will Be Suspended',
  body: `Dear Valued Customer,

We have detected unusual activity on your accout. Your account will be suspended within 24 hours unless you verify your information immediately.

Please click the link below to confirm your identity and prevent account closure:

You must provide your password and credit card details to verify ownership.

Failure to comply will result in permanent account suspension and legal action.

Thank you,
PayPal Security Team`,
  links: 'http://paypa1-verify.tk/secure-login\nhttp://192.168.1.100/verify',
};

// Made-up sample for trying the new financial-scam rules.
export const EXAMPLE_FEE = {
  sender: 'hr@example-internships.com',
  subject: 'Internship selection confirmed',
  body: `Congratulations, you are selected for our internship programme.

Please pay the registration fee of Rs. 999 to confirm your seat. Only 10 seats left, register now.
The stipend is subject to performance after the first month. No interview is required.
Contact us on WhatsApp for the payment details.`,
  links: 'https://example-internships.com/register',
};
