import time
import socket
from dataclasses import dataclass, asdict


import dns.resolver


try:
    import whois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False


@dataclass
class ContextFeatures:
    a_count: int = 0
    ns_count: int = 0
    mx_count: int = 0
    ttl_min: int = 0
    ttl_mean: float = 0.0
    has_mx: int = 0
    domain_age_days: int = -1  # -1 unknown


def _dns_query(name: str, rtype: str, timeout: float = 2.0):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        ans = resolver.resolve(name, rtype)
        ttls = [ans.rrset.ttl] if ans.rrset is not None else []
        return ans, ttls
    except Exception:
        return None, []


def extract_dns_features(domain: str) -> ContextFeatures:
    feat = ContextFeatures()

    # A
    ans_a, ttls_a = _dns_query(domain, "A")
    if ans_a is not None:
        feat.a_count = len(ans_a)
    ttls = []
    ttls += ttls_a

    # NS
    ans_ns, ttls_ns = _dns_query(domain, "NS")
    if ans_ns is not None:
        feat.ns_count = len(ans_ns)
    ttls += ttls_ns

    # MX
    ans_mx, ttls_mx = _dns_query(domain, "MX")
    if ans_mx is not None:
        feat.mx_count = len(ans_mx)
    ttls += ttls_mx
    feat.has_mx = 1 if feat.mx_count > 0 else 0

    if ttls:
        feat.ttl_min = int(min(ttls))
        feat.ttl_mean = float(sum(ttls) / len(ttls))

    return feat


def extract_whois_age_days(domain: str) -> int:
    if not WHOIS_AVAILABLE:
        return -1
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if cd is None:
            return -1
        # naive: seconds difference
        age_days = int((time.time() - cd.timestamp()) / 86400)
        return age_days
    except Exception:
        return -1


def extract_context_features(domain: str, use_whois: bool = False) -> dict:
    dns_feat = extract_dns_features(domain)
    if use_whois:
        dns_feat.domain_age_days = extract_whois_age_days(domain)
    return asdict(dns_feat)
