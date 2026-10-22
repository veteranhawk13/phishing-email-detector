# 🛡️ Phishing Email Detector

A React web app that scores emails for phishing risk (0 to 100%) by combining hand-written rules with a trained machine-learning model. Everything runs in your browser: nothing you paste is sent anywhere.

**Live demo:** https://veteranhawk13.github.io/phishing-email-detector/

## How it works

The final score is **60% rules + 40% trained model**.

1. **Rules** (`src/analyze.js`): lookalike domains, urgent or threatening language, requests for passwords or card numbers, generic greetings, prize claims, and risky links (IP addresses, URL shorteners, plain HTTP).
2. **Trained model** (`src/model.js`, `public/model.json`): TF-IDF features and logistic regression, trained on the CEAS-08 email dataset (about 39,000 labeled emails). The weights are exported to JSON and run directly in the browser.

### Model results (held-out 20% test set)

| Metric | Value |
|---|---|
| Accuracy | 99.66% |
| Precision | 99.68% |
| Recall | 99.70% |
| F1 | 99.69% |

**Read these numbers carefully.** CEAS-08 is a 2008 spam/phishing challenge dataset. Its legitimate emails are largely mailing-list messages, so the model partly learned "2008 spam vs. mailing-list chatter". Real-world accuracy on modern phishing and on ordinary business email (order confirmations, newsletters) will be lower, and the model can give false alarms on such emails. That is why it is blended with the rules instead of being trusted alone.

## Features

- Paste a whole email, or load an `.eml` file, and the fields fill in automatically
- Risk score with red flags, warnings and positive indicators
- Shows the rules score and the model score separately
- Dark and light themes

## Run it locally

You need [Node.js](https://nodejs.org) 18 or newer.

```bash
git clone https://github.com/veteranhawk13/phishing-email-detector.git
cd phishing-email-detector
npm install
npm run dev
```

Then open http://localhost:3000.

## Retrain the model

```bash
pip install -r model/requirements.txt
python model/train.py path/to/CEAS_08.csv
```

The CSV needs `subject`, `body` and `label` columns (1 = phishing/spam, 0 = legitimate). The script prints the test metrics and rewrites `public/model.json`. The CEAS-08 file is available in the public GitHub repo `PHP4Life/Phishing-Email-Dataset`. Using a more recent dataset would improve results on modern phishing.

## Project structure

```
src/
  App.jsx       User interface
  analyze.js    Rules and score blending
  model.js      Runs the trained model in the browser
  parse.js      Email and .eml parser
  styles.css    Themes and styling
model/
  train.py      Training script
public/
  model.json    Trained weights (about 360 KB)
```

## Limitations

A learning project, not a security product. It can miss sophisticated phishing and flag legitimate emails. Never click links in suspicious emails, and use your email provider's own protection as well.

## Tech

React 18, Vite, scikit-learn (training only).
