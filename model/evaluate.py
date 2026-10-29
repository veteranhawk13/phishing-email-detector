"""
evaluate.py - check how good the saved model is on a labeled CSV file.

It loads public/model.json (made by train.py) and scores every email the same
way the website does, so the results here match what the app would say.

Run it on a dataset the model has NOT seen before, otherwise the numbers
will look better than they really are.

Examples:
    python model/evaluate.py other_data.csv
    python model/evaluate.py other_data.csv --show-errors 5
    python model/evaluate.py data.csv --subject-col title --body-col text --label-col is_phish
    python model/evaluate.py CEAS_08.csv --reproduce-holdout

The CSV needs a subject, a body and a label column.
Label: 1 = phishing/spam, 0 = legitimate (words like "phishing"/"legitimate" also work).
"""
import argparse
import json
import math
import re
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, roc_auc_score, confusion_matrix)
from sklearn.model_selection import train_test_split

WORD = re.compile(r'\w{2,}')   # words with 2+ characters, like the JS code

PHISH_LABELS = {'1', 'phishing', 'phish', 'spam', 'malicious', 'fraud', 'true', 'yes'}
SAFE_LABELS = {'0', 'legitimate', 'legit', 'ham', 'safe', 'benign', 'false', 'no'}


def load_model(path):
    with open(path) as f:
        model = json.load(f)
    # map each word to its position so lookups are fast
    model['index'] = {word: i for i, word in enumerate(model['vocab'])}
    model['idf'] = np.array(model['idf'])
    model['coef'] = np.array(model['coef'])
    return model


def score_email(model, subject, body):
    """Return the chance (0 to 1) that the email is phishing."""
    text = (subject + ' \n ' + body[:5000]).lower()

    # count how many times each known word appears
    counts = Counter()
    for word in WORD.findall(text):
        if word in model['index']:
            counts[model['index'][word]] += 1

    if not counts:
        return None   # nothing the model knows, so no score

    positions = np.array(list(counts.keys()))
    freq = np.array(list(counts.values()), dtype=float)

    # tf-idf: (1 + log(count)) * idf, then scale so the vector has length 1
    tfidf = (1 + np.log(freq)) * model['idf'][positions]
    length = np.sqrt(np.sum(tfidf ** 2)) or 1.0
    tfidf = tfidf / length

    # logistic regression: weighted sum, then sigmoid
    z = model['intercept'] + np.sum(tfidf * model['coef'][positions])
    return 1 / (1 + math.exp(-z))


def clean_label(value):
    text = str(value).strip().lower()
    if text in PHISH_LABELS:
        return 1
    if text in SAFE_LABELS:
        return 0
    try:
        return 1 if float(text) >= 1 else 0
    except ValueError:
        raise SystemExit(f'Cannot understand label "{value}". Use 0/1 or phishing/legitimate.')


def load_data(path, subject_col, body_col, label_col):
    df = pd.read_csv(path)
    for col in (subject_col, body_col, label_col):
        if col not in df.columns:
            raise SystemExit(f'Column "{col}" not found in {path}. Columns are: {list(df.columns)}')

    data = pd.DataFrame()
    data['subject'] = df[subject_col].fillna('').astype(str)
    data['body'] = df[body_col].fillna('').astype(str)
    data['label'] = df[label_col].map(clean_label)

    # remove duplicate emails (train.py does the same)
    data['text'] = data['subject'] + ' \n ' + data['body'].str.slice(0, 5000)
    data = data.drop_duplicates(subset='text').reset_index(drop=True)
    return data


def evaluate(name, data, model, threshold, show_errors):
    data = data.copy()
    data['prob'] = [score_email(model, s, b) for s, b in zip(data['subject'], data['body'])]

    skipped = data['prob'].isna().sum()
    data = data.dropna(subset=['prob'])
    data['pred'] = (data['prob'] >= threshold).astype(int)

    print(f'\n--- {name} ---')
    print(f'Emails: {len(data)} (phishing: {data["label"].sum()}, legitimate: {(data["label"] == 0).sum()})')
    if skipped:
        print(f'Skipped {skipped} emails with no known words')

    if data['label'].nunique() < 2:
        print('Only one class in this file, so precision/recall do not make sense.')
        print(f'Share flagged as phishing: {data["pred"].mean():.4f}')
        return

    y, pred = data['label'], data['pred']
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()

    print(f'Threshold:  {threshold}')
    print(f'Accuracy:   {accuracy_score(y, pred):.4f}')
    print(f'Precision:  {precision_score(y, pred, zero_division=0):.4f}')
    print(f'Recall:     {recall_score(y, pred, zero_division=0):.4f}')
    print(f'F1 score:   {f1_score(y, pred, zero_division=0):.4f}')
    print(f'ROC AUC:    {roc_auc_score(y, data["prob"]):.4f}')
    print(f'Legit emails wrongly flagged: {fp / max(fp + tn, 1):.4f}')
    print(f'Phishing emails missed:       {fn / max(fn + tp, 1):.4f}')
    print(f'Confusion matrix [[TN, FP], [FN, TP]]: [[{tn}, {fp}], [{fn}, {tp}]]')

    if show_errors:
        wrong_flags = data[(y == 0) & (pred == 1)].sort_values('prob', ascending=False)
        missed = data[(y == 1) & (pred == 0)].sort_values('prob')

        print('\nLegit emails flagged as phishing:')
        for _, row in wrong_flags.head(show_errors).iterrows():
            print(f'  {row["prob"]:.3f}  {row["subject"][:80]}')

        print('\nPhishing emails that were missed:')
        for _, row in missed.head(show_errors).iterrows():
            print(f'  {row["prob"]:.3f}  {row["subject"][:80]}')


def main():
    parser = argparse.ArgumentParser(description='Evaluate the phishing model on a CSV file.')
    parser.add_argument('csv', nargs='+', help='one or more labeled CSV files')
    parser.add_argument('--model', default='public/model.json', help='path to model.json')
    parser.add_argument('--subject-col', default='subject')
    parser.add_argument('--body-col', default='body')
    parser.add_argument('--label-col', default='label')
    parser.add_argument('--threshold', type=float, default=0.5, help='score needed to call it phishing')
    parser.add_argument('--show-errors', type=int, default=0, help='show N mistakes of each kind')
    parser.add_argument('--reproduce-holdout', action='store_true',
                        help='only use the same 20%% test split that train.py used (for the CEAS-08 file)')
    args = parser.parse_args()

    model = load_model(args.model)
    print(f'Loaded model with {len(model["vocab"])} words')

    for path in args.csv:
        data = load_data(path, args.subject_col, args.body_col, args.label_col)
        name = path

        if args.reproduce_holdout:
            # same settings as train.py so we get the exact same test emails
            _, data = train_test_split(data, test_size=0.2, random_state=42, stratify=data['label'])
            name += ' (test split from train.py)'

        evaluate(name, data, model, args.threshold, args.show_errors)


if __name__ == '__main__':
    main()
