// Runs the trained TF-IDF + logistic regression model in the browser.
// The weights come from public/model.json, produced by model/train.py.
let modelPromise = null;

export function loadModel() {
  if (!modelPromise) {
    const base = (typeof import.meta !== 'undefined' && import.meta.env?.BASE_URL) || '/';
    modelPromise = fetch(`${base}model.json`)
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('model.json not found'))))
      .then((m) => {
        const index = new Map();
        m.vocab.forEach((t, i) => index.set(t, i));
        return { ...m, index };
      })
      .catch(() => null); // app still works with rules only
  }
  return modelPromise;
}

// Probability (0..1) that the text is phishing/spam.
export function predict(model, subject, body) {
  const text = `${subject || ''} \n ${(body || '').slice(0, 5000)}`.toLowerCase();
  const tokens = text.match(/[\p{L}\p{N}_]{2,}/gu) || [];
  const counts = new Map();
  for (const t of tokens) {
    const i = model.index.get(t);
    if (i !== undefined) counts.set(i, (counts.get(i) || 0) + 1);
  }
  if (!counts.size) return { probability: null, topWords: [] };

  let norm = 0;
  const weighted = [];
  for (const [i, c] of counts) {
    const v = (1 + Math.log(c)) * model.idf[i];
    weighted.push([i, v]);
    norm += v * v;
  }
  norm = Math.sqrt(norm) || 1;

  let z = model.intercept;
  const contributions = [];
  for (const [i, v] of weighted) {
    const contrib = (v / norm) * model.coef[i];
    z += contrib;
    contributions.push([model.vocab[i], contrib]);
  }
  contributions.sort((a, b) => b[1] - a[1]);
  return {
    probability: 1 / (1 + Math.exp(-z)),
    topWords: contributions.filter((c) => c[1] > 0).slice(0, 6).map((c) => c[0]),
  };
}
