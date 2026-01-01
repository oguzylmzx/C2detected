import re
import pandas as pd
from urllib.parse import urlparse

def normalize_domain(s: str) -> str:
    s = s.strip().lower()
    if not s:
        return ""
    # URL ise parse et
    if "://" in s:
        try:
            s = urlparse(s).netloc
        except:
            pass
    # path/query kırp
    s = s.split("/")[0]
    # www kaldır
    s = re.sub(r"^www\.", "", s)
    # port kaldır
    s = s.split(":")[0]
    # sadece izinli karakterler (harf, rakam, nokta, tire)
    s = re.sub(r"[^a-z0-9\.\-]", "", s)
    # baş/son nokta/tire temizle
    s = s.strip(".-")
    return s

def load_list(path: str, label: int):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            d = normalize_domain(line)
            if d and "." in d:
                rows.append((d, label))
    return rows

def main():
    benign = load_list("data/raw/benign.txt", 0)
    mal = load_list("data/raw/malicious.txt", 1)

    df = pd.DataFrame(benign + mal, columns=["domain", "label"])
    df = df.drop_duplicates(subset=["domain"]).reset_index(drop=True)

    df.to_csv("data/processed/dataset.csv", index=False)
    print("saved -> data/processed/dataset.csv | rows=", len(df))
    print(df["label"].value_counts())

if __name__ == "__main__":
    main()
