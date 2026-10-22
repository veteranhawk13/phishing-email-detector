"""Train a TF-IDF + logistic regression phishing/spam classifier and export it as JSON
so the React app can run it in the browser (no backend needed).

Usage:  python model/train.py path/to/CEAS_08.csv
Expects columns: subject, body, label (1 = phishing/spam, 0 = legitimate).
"""
import json, sys
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

csv = sys.argv[1] if len(sys.argv) > 1 else 'CEAS_08.csv'
df = pd.read_csv(csv)
df['subject'] = df['subject'].fillna('')
df['body'] = df['body'].fillna('').str.slice(0, 5000)
# Sender is deliberately NOT used: it leaks dataset-specific domains.
df['text'] = df['subject'] + ' \n ' + df['body']
df = df.drop_duplicates(subset='text')

X_train, X_test, y_train, y_test = train_test_split(
    df['text'], df['label'], test_size=0.2, random_state=42, stratify=df['label'])

vec = TfidfVectorizer(lowercase=True, token_pattern=r'(?u)\b\w\w+\b', max_features=15000,
                      min_df=5, sublinear_tf=True, norm='l2')
Xtr = vec.fit_transform(X_train)
clf = LogisticRegression(C=4.0, max_iter=2000)
clf.fit(Xtr, y_train)

pred = clf.predict(vec.transform(X_test))
metrics = {
    'accuracy': round(accuracy_score(y_test, pred), 4),
    'precision': round(precision_score(y_test, pred), 4),
    'recall': round(recall_score(y_test, pred), 4),
    'f1': round(f1_score(y_test, pred), 4),
    'train_size': int(len(X_train)), 'test_size': int(len(X_test)),
    'confusion_matrix [[TN,FP],[FN,TP]]': confusion_matrix(y_test, pred).tolist(),
}
print(json.dumps(metrics, indent=2))

vocab = vec.vocabulary_
terms = [None] * len(vocab)
for t, i in vocab.items():
    terms[i] = t
model = {
    'vocab': terms,
    'idf': [round(float(x), 4) for x in vec.idf_],
    'coef': [round(float(x), 4) for x in clf.coef_[0]],
    'intercept': round(float(clf.intercept_[0]), 4),
    'metrics': metrics,
    'dataset': 'CEAS-08 (spam/phishing vs legitimate email, 2008)',
}
with open('public/model.json', 'w') as f:
    json.dump(model, f, separators=(',', ':'))
print('saved public/model.json')

# Top words, for sanity checking
coef = clf.coef_[0]
order = np.argsort(coef)
print('Most phishing-like:', [terms[i] for i in order[-15:][::-1]])
print('Most legitimate-like:', [terms[i] for i in order[:15]])
