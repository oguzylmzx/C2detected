def stage2_score(ctx: dict) -> dict:
    """
    Basit ama sunumluk güçlü bir doğrulama skoru.
    Amaç: Stage-1 'şüpheli' dediğinde DNS/WHOIS sinyalleriyle teyit etmek.
    """
    score = 0
    reasons = []

    ttl_min = ctx.get("ttl_min", 0)
    a_count = ctx.get("a_count", 0)
    ns_count = ctx.get("ns_count", 0)
    has_mx = ctx.get("has_mx", 0)
    age = ctx.get("domain_age_days", -1)

    # Kısa TTL -> fast-flux / dinamik altyapı ihtimali
    if ttl_min and ttl_min <= 300:
        score += 25
        reasons.append(f"Low TTL (ttl_min={ttl_min})")

    # Çok fazla A kaydı -> flux belirtisi olabilir
    if a_count >= 5:
        score += 20
        reasons.append(f"Many A records (a_count={a_count})")

    # MX yok -> mail amaçlı değil, C2/loader domainlerde sık
    if has_mx == 0:
        score += 10
        reasons.append("No MX record")

    # NS yok/az -> bazı anormal durumlar
    if ns_count == 0:
        score += 10
        reasons.append("No NS record")

    # WHOIS age (opsiyonel)
    if age != -1 and age < 30:
        score += 25
        reasons.append(f"Very new domain (age_days={age})")

    # 0-100 clamp
    score = max(0, min(100, score))
    return {"stage2_score": score, "reasons": reasons}
