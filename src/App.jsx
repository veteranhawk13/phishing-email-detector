import { useEffect, useRef, useState } from 'react';
import { analyzeEmail, EXAMPLE } from './analyze.js';
import { parseEmail } from './parse.js';
import { loadModel, predict } from './model.js';

const EMPTY = { sender: '', subject: '', body: '', links: '' };

function riskLevel(score) {
  if (score < 30) return { cls: 'safe', label: '✓ Appears Safe' };
  if (score < 60) return { cls: 'suspicious', label: '⚠ Suspicious - Use Caution' };
  return { cls: 'dangerous', label: '🚨 High Risk - Likely Phishing' };
}

function IndicatorList({ items, type, icon, emptyTitle }) {
  return (
    <div className="indicator-list">
      {items.length ? (
        items.map((item, i) => (
          <div key={i} className={`indicator ${type}`}>
            <div className="indicator-icon">{icon}</div>
            <div className="indicator-content">
              <div className="indicator-title">{item.title}</div>
              <div className="indicator-description">{item.description}</div>
            </div>
          </div>
        ))
      ) : (
        <div className={`indicator ${type === 'safe' && emptyTitle.startsWith('No Positive') ? '' : 'safe'}`}>
          <div className="indicator-icon">{emptyTitle.startsWith('No Positive') ? 'ℹ️' : '✓'}</div>
          <div className="indicator-content">
            <div className="indicator-title">{emptyTitle}</div>
          </div>
        </div>
      )}
    </div>
  );
}

function Section({ icon, title, children }) {
  return (
    <div className="analysis-section">
      <div className="section-title">
        <span className="section-title-icon">{icon}</span>
        {title}
      </div>
      {children}
    </div>
  );
}

export default function App() {
  const [form, setForm] = useState(EMPTY);
  const [result, setResult] = useState(null);
  const [raw, setRaw] = useState('');
  const [notice, setNotice] = useState('');
  const [theme, setTheme] = useState(() => {
    try { return localStorage.getItem('theme') || 'dark'; } catch { return 'dark'; }
  });
  const [model, setModel] = useState(null);
  const [modelState, setModelState] = useState('loading');
  const resultsRef = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => {
    loadModel().then((m) => {
      setModel(m);
      setModelState(m ? 'ready' : 'missing');
    });
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('theme', theme); } catch {}
  }, [theme]);

  const fillFromRaw = (text) => {
    if (!text.trim()) {
      setNotice('The box is empty. Paste an email into it first, or click "Paste from clipboard".');
      return;
    }
    const parsed = parseEmail(text);
    setForm(parsed);
    setResult(null);
    const n = parsed.links ? parsed.links.split('\n').length : 0;
    setNotice(`Fields filled: ${parsed.sender ? 'sender' : 'no sender found'}, ${parsed.subject ? 'subject' : 'no subject found'}, body, ${n} link${n === 1 ? '' : 's'}.`);
  };

  const pasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setRaw(text);
      fillFromRaw(text);
    } catch {
      setNotice('Clipboard access was blocked. Paste into the box below instead (Ctrl/Cmd+V).');
    }
  };

  const loadFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setRaw(text);
    fillFromRaw(text);
    e.target.value = '';
  };

  const update = (field) => (e) => setForm((f) => ({ ...f, [field]: e.target.value }));

  const handleAnalyze = () => {
    const { sender, subject, body } = form;
    if (!sender.trim() && !subject.trim() && !body.trim()) {
      alert('Please enter at least some email information to analyze.');
      return;
    }
    const input = {
      sender: form.sender.trim(),
      subject: form.subject.trim(),
      body: form.body.trim(),
      links: form.links.trim(),
    };
    const ml = model ? predict(model, input.subject, input.body) : null;
    setResult(analyzeEmail(input, ml));
    setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }), 0);
  };

  const level = result ? riskLevel(result.riskScore) : null;

  return (
    <div className="container">
      <div className="header">
        <button className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label="Toggle theme">
          {theme === 'dark' ? '☀️ Light' : '🌙 Dark'}
        </button>
        <h1>🛡️ Phishing Email Detector</h1>
        <p>Analyze emails for suspicious patterns and potential threats</p>
        <p className="model-status">
          {modelState === 'ready' && `Rules + trained model (${(model.metrics.f1 * 100).toFixed(1)}% F1 on its test set)`}
          {modelState === 'loading' && 'Loading trained model…'}
          {modelState === 'missing' && 'Trained model not found: using rules only'}
        </p>
      </div>

      <div className="content">
        <div className="input-section">
          <div className="paste-box">
            <div className="paste-head">
              <strong>Quick import</strong>
              <span>Paste a whole email (with or without headers) or load an .eml file. The fields fill themselves.</span>
            </div>
            <textarea
              className="raw"
              placeholder={'From: Name <sender@example.com>\nSubject: ...\n\nEmail text...'}
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              onPaste={(e) => {
                const text = e.clipboardData.getData('text');
                setTimeout(() => fillFromRaw(text), 0);
              }}
            />
            <div className="paste-actions">
              <button className="chip primary" onClick={pasteFromClipboard}>📋 Paste from clipboard</button>
              <button className="chip" onClick={() => fileRef.current?.click()}>📎 Open .eml / .txt</button>
              <input ref={fileRef} type="file" accept=".eml,.txt,.html,.htm,message/rfc822" hidden onChange={loadFile} />
            </div>
            {notice && <div className="notice">{notice}</div>}
          </div>

          <div className="input-group">
            <label htmlFor="senderEmail">Sender Email Address:</label>
            <input id="senderEmail" type="email" placeholder="e.g., support@paypa1.com" value={form.sender} onChange={update('sender')} />
          </div>
          <div className="input-group">
            <label htmlFor="subject">Email Subject:</label>
            <input id="subject" type="text" placeholder="e.g., URGENT: Verify your account" value={form.subject} onChange={update('subject')} />
          </div>
          <div className="input-group">
            <label htmlFor="emailBody">Email Body:</label>
            <textarea id="emailBody" placeholder="Paste the email content here..." value={form.body} onChange={update('body')} />
          </div>
          <div className="input-group">
            <label htmlFor="links">Links in Email (one per line):</label>
            <textarea
              id="links"
              style={{ minHeight: 80 }}
              placeholder={'http://example.com\nhttps://suspicious-site.net'}
              value={form.links}
              onChange={update('links')}
            />
          </div>

          <button className="btn" onClick={handleAnalyze}>🔍 Analyze Email</button>
          <button className="example-btn" onClick={() => { setForm(EXAMPLE); setResult(null); setRaw(''); setNotice(''); }}>
            Load Example Phishing Email
          </button>
          <button className="example-btn" onClick={() => { setForm(EMPTY); setResult(null); setRaw(''); setNotice(''); }}>
            Clear
          </button>
        </div>

        {result && (
          <div className="results" ref={resultsRef}>
            <div className={`risk-score ${level.cls}`}>
              <h2>Risk Assessment</h2>
              <div className="risk-percentage">{result.riskScore}%</div>
              <div className="risk-label">{level.label}</div>
              <div className="risk-breakdown">
                Rules: {result.rulesScore}%
                {' · '}
                Trained model: {result.mlPercent === null ? 'n/a' : `${result.mlPercent}%`}
              </div>
            </div>

            <Section icon="🚨" title="Red Flags Detected">
              <IndicatorList items={result.redFlags} type="red-flag" icon="🚨" emptyTitle="No Critical Red Flags" />
            </Section>
            <Section icon="⚠️" title="Warning Signs">
              <IndicatorList items={result.warnings} type="warning" icon="⚠️" emptyTitle="No Warnings" />
            </Section>
            <Section icon="✅" title="Positive Indicators">
              <IndicatorList items={result.positives} type="safe" icon="✅" emptyTitle="No Positive Indicators Found" />
            </Section>

            <div className="tips">
              <h3>🔐 How to Protect Yourself:</h3>
              <ul>
                <li>Never click links in suspicious emails - visit websites directly by typing the URL</li>
                <li>Verify sender identity through official channels before responding</li>
                <li>Look for spelling errors, urgent language, and requests for sensitive information</li>
                <li>Hover over links (don't click) to see the actual destination URL</li>
                <li>Enable two-factor authentication on all important accounts</li>
                <li>Report phishing attempts to your IT department or email provider</li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
