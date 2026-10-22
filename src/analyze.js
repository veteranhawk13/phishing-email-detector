// Pure analysis logic: no DOM, easy to test.
export function analyzeEmail({ sender, subject, body, links }, ml = null) {
  const redFlags = [];
  const warnings = [];
  const positives = [];
  let riskScore = 0;

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

    const sensitive = ['password', 'credit card', 'social security', 'ssn', 'bank account', 'pin', 'verification code'];
    const foundSensitive = sensitive.filter((t) => b.includes(t));
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

    const greetings = ['dear customer', 'dear user', 'dear member', 'valued customer'];
    if (greetings.some((g) => b.includes(g))) {
      warnings.push({
        title: 'Generic Greeting',
        description: 'Uses generic greeting instead of your name. Legitimate companies personalize communications.',
      });
      riskScore += 8;
    }

    if (b.includes('won') || b.includes('prize') || b.includes('lottery')) {
      redFlags.push({
        title: 'Unsolicited Prize Claim',
        description: "Claims you won something you didn't enter. Classic phishing/scam tactic.",
      });
      riskScore += 25;
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
    } else if (ml.probability >= 0.5) {
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

  return { riskScore: finalScore, rulesScore, mlPercent, redFlags, warnings, positives };
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
