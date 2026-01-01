import sys
import pandas as pd
import joblib

from src.features import lexical_features

# Stage-2 opsiyonel: import başarısızsa bile Stage-1 çalışsın
try:
    from src.context_features import extract_context_features
    from src.stage2_verifier import stage2_score
    STAGE2_AVAILABLE = True
except Exception:
    STAGE2_AVAILABLE = False

THRESHOLD_STAGE1 = 0.5
THRESHOLD_STAGE2_CONFIRM = 30  # Stage-2 doğrulama eşiği


def predict_domain(domain: str):
    lex = lexical_features(domain)
    X = pd.DataFrame([{"domain": domain, **lex}])

    pipe = joblib.load("models/c2_domain_model.joblib")
    p1 = float(pipe.predict_proba(X)[0, 1])  # stage-1 probability

    result = {
        "domain": domain,
        "stage1_prob": p1,
        "stage1_label": "suspicious" if p1 >= THRESHOLD_STAGE1 else "benign",
        "lexical": lex,
        "stage2_score": None,
        "stage2_reasons": [],
        "final_label": None,
        "final_risk": None,
    }

    # Stage-1 benign -> directly finalize
    if p1 < THRESHOLD_STAGE1:
        result["final_label"] = "Benign olabilir"
        result["final_risk"] = int(round(p1 * 100))
        return result

    # Stage-1 suspicious -> try Stage-2 if available
    if not STAGE2_AVAILABLE:
        result["final_label"] = "Şüpheli (Stage-2 yok)"
        result["final_risk"] = int(round(p1 * 100))
        return result

    try:
        ctx = extract_context_features(domain, use_whois=False)
        v = stage2_score(ctx)

        s2 = v.get("stage2_score", 0)
        reasons = v.get("reasons", [])

        # Risk scale (0-100): Stage1 prob -> 0-100
        risk1 = p1 * 100.0
        final_risk = int(round((risk1 * 0.70) + (s2 * 0.30)))

        # GATING
        if s2 < THRESHOLD_STAGE2_CONFIRM:
            final_label = "Şüpheli (Doğrulanmadı)"
        else:
            final_label = "C2 olabilir" if final_risk >= 50 else "Benign olabilir"

        result.update({
            "context": ctx,
            "stage2_score": int(s2),
            "stage2_reasons": reasons,
            "final_label": final_label,
            "final_risk": final_risk
        })
        return result

    except Exception as e:
        # Stage-2 failed -> don't crash
        result["final_label"] = "Şüpheli (Doğrulanamadı - DNS fail)"
        result["final_risk"] = int(round(p1 * 100))
        result["stage2_reasons"] = [f"stage2_error={type(e).__name__}"]
        return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m src.predict example.com")
        sys.exit(1)

    domain = sys.argv[1].strip().lower()
    r = predict_domain(domain)

    print("Domain:", r["domain"])
    print("Stage-1 prob:", round(r["stage1_prob"], 4), "| label:", r["stage1_label"])
    if r["stage2_score"] is not None:
        print("Stage-2 score:", r["stage2_score"], "/ 100")
        print("Stage-2 reasons:", ", ".join(r["stage2_reasons"]) if r["stage2_reasons"] else "-")
    print("FINAL:", r["final_label"], "| risk:", r["final_risk"], "/ 100")


if __name__ == "__main__":
    main()
