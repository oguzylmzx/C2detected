import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, average_precision_score, roc_auc_score

from src.features import lexical_features

def main():
    df = pd.read_csv("data/processed/dataset.csv")
    lex = df["domain"].apply(lexical_features).apply(pd.Series)
    X = pd.concat([df[["domain"]], lex], axis=1)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipe = joblib.load("models/c2_domain_model.joblib")
    proba = pipe.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)

    print("Confusion Matrix:\n", confusion_matrix(y_test, pred))
    print("\nReport:\n", classification_report(y_test, pred, digits=4))
    print("ROC-AUC:", roc_auc_score(y_test, proba))
    print("PR-AUC :", average_precision_score(y_test, proba))

if __name__ == "__main__":
    main()
