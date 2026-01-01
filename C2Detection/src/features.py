import math
import numpy as np

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def lexical_features(domain: str) -> dict:
    # domain: "a1b2c3.example-xyz.com"
    parts = domain.split(".")
    tld = parts[-1] if len(parts) >= 2 else ""
    sub_count = max(0, len(parts) - 2)

    digits = sum(ch.isdigit() for ch in domain)
    hyphens = domain.count("-")

    return {
        "len": len(domain),
        "digits_ratio": digits / max(1, len(domain)),
        "hyphen_ratio": hyphens / max(1, len(domain)),
        "subdomain_count": sub_count,
        "entropy": shannon_entropy(domain.replace(".", "")),
        "tld": tld
    }
