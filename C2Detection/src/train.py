import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression

from src.features import lexical_features

def main():
    df = pd.read_csv("data/processed/dataset.csv")
    # lexical feature dataframe
    lex = df["domain"].apply(lexical_features).apply(pd.Series)
    X = pd.concat([df[["domain"]], lex], axis=1)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ColumnTransformer: domain -> TFIDF, tld -> OneHot, numeric -> passthrough
    pre = ColumnTransformer(
        transformers=[
            ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3,5), min_df=2), "domain"),
            ("tld", OneHotEncoder(handle_unknown="ignore"), ["tld"]),
        ],
        remainder="passthrough"
    )

    clf = LogisticRegression(max_iter=2000, class_weight="balanced")

    pipe = Pipeline([
        ("preprocess", pre),
        ("model", clf)
    ])

    pipe.fit(X_train, y_train)

    joblib.dump(pipe, "models/c2_domain_model.joblib")
    print("saved model -> models/c2_domain_model.joblib")
    print("Train rows:", len(X_train), "Test rows:", len(X_test))

if __name__ == "__main__":
    main()
