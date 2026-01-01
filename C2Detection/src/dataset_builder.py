import argparse
import ipaddress
import re
import zipfile
from urllib.parse import urlparse

import pandas as pd


# ---------- Helpers ----------
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def normalize_domain(s: str) -> str:
    """
    Normalize a domain or URL into a clean host.
    Keeps only [a-z0-9.-], strips ports, www, paths.
    """
    if s is None:
        return ""
    s = str(s).strip().lower()
    if not s:
        return ""

    # If it's a URL, parse host
    if "://" in s:
        try:
            s = urlparse(s).netloc
        except Exception:
            pass

    # Remove path if still present
    s = s.split("/")[0]

    # Remove credentials if any user:pass@
    if "@" in s:
        s = s.split("@")[-1]

    # Remove port
    s = s.split(":")[0]

    # Remove www.
    s = re.sub(r"^www\.", "", s)

    # Keep domain-safe chars
    s = re.sub(r"[^a-z0-9\.\-]", "", s)
    s = s.strip(".-")

    return s


def looks_like_domain(host: str) -> bool:
    """
    Checks if host looks like a valid domain (not perfect, but good for MVP).
    """
    if not host or "." not in host:
        return False
    if len(host) > 253:
        return False
    if host.startswith(".") or host.endswith("."):
        return False
    return bool(DOMAIN_RE.match(host))


def root_domain(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def read_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def read_tranco_like(path: str, limit: int) -> list[str]:
    """
    Reads a "top domains" list. Your top-1m.csv is 1 domain per line.
    Works also for rank,domain CSV formats and .zip containing such file.
    """
    domains = []

    if path.lower().endswith(".zip"):
        with zipfile.ZipFile(path, "r") as z:
            names = [n for n in z.namelist() if not n.endswith("/")]
            if not names:
                raise ValueError(f"Zip is empty: {path}")
            name = names[0]
            with z.open(name) as f:
                # try CSV parse
                try:
                    df = pd.read_csv(f, header=None, dtype=str, encoding_errors="ignore")
                    if df.shape[1] >= 2:
                        domains = df.iloc[:, 1].astype(str).tolist()
                    else:
                        domains = df.iloc[:, 0].astype(str).tolist()
                except Exception:
                    f.seek(0)
                    text = f.read().decode("utf-8", errors="ignore").splitlines()
                    domains = text
    else:
        # try CSV read; if it's one-column list, it will still work
        try:
            df = pd.read_csv(path, header=None, dtype=str, encoding_errors="ignore")
            if df.shape[1] >= 2:
                domains = df.iloc[:, 1].astype(str).tolist()
            else:
                domains = df.iloc[:, 0].astype(str).tolist()
        except Exception:
            domains = read_lines(path)

    cleaned = []
    seen = set()
    for d in domains:
        nd = normalize_domain(d)
        if not nd:
            continue
        # keep only real domains (benign list should be domains anyway)
        if not looks_like_domain(nd):
            continue
        if nd in seen:
            continue
        seen.add(nd)
        cleaned.append(nd)
        if limit and len(cleaned) >= limit:
            break
    return cleaned


def read_urlhaus_plaintext(path: str, limit: int, keep_ips: bool) -> list[str]:
    """
    Reads URLhaus plain-text list (one URL per line) and extracts hosts.
    Your file 'online_urls.txt' is exactly this format.
    """
    lines = read_lines(path)

    cleaned = []
    seen = set()

    for line in lines:
        host = normalize_domain(line)  # works for URL and for raw host
        if not host:
            continue

        # Filter IPs unless keep_ips is set
        if is_ip(host) and not keep_ips:
            continue

        # If not IP, require it to look like domain
        if not is_ip(host) and not looks_like_domain(host):
            continue

        if host in seen:
            continue
        seen.add(host)
        cleaned.append(host)

        if limit and len(cleaned) >= limit:
            break

    return cleaned


def write_list(path: str, items: list[str]):
    with open(path, "w", encoding="utf-8") as f:
        for x in items:
            f.write(x + "\n")


def main():
    parser = argparse.ArgumentParser(description="Build benign.txt and malicious.txt (domain-based) from top list + URLhaus plain-text.")
    parser.add_argument("--top", required=True, help="Path to benign top list (e.g., top-1m.csv or tranco.csv/zip)")
    parser.add_argument("--urlhaus", required=True, help="Path to URLhaus plain-text online_urls.txt (one URL per line)")
    parser.add_argument("--benign_limit", type=int, default=5000, help="Max benign domains to keep")
    parser.add_argument("--malicious_limit", type=int, default=5000, help="Max malicious hosts to keep")
    parser.add_argument("--balance", action="store_true", help="Balance classes by downsampling to min count")
    parser.add_argument("--keep_ips", action="store_true", help="Keep IP hosts in malicious list (default: filter out IPs)")
    parser.add_argument("--out_dir", default="data/raw", help="Output directory for benign.txt and malicious.txt")
    args = parser.parse_args()

    benign = read_tranco_like(args.top, args.benign_limit)
    malicious = read_urlhaus_plaintext(args.urlhaus, args.malicious_limit, keep_ips=args.keep_ips)

    # quick root-domain uniq to reduce leakage-ish duplicates
    benign = list({root_domain(d): d for d in benign}.values())
    malicious = list({root_domain(d) if not is_ip(d) else d: d for d in malicious}.values())

    if args.balance:
        n = min(len(benign), len(malicious))
        benign = benign[:n]
        malicious = malicious[:n]

    out_benign = f"{args.out_dir}/benign.txt"
    out_mal = f"{args.out_dir}/malicious.txt"

    write_list(out_benign, benign)
    write_list(out_mal, malicious)

    print("✅ Wrote:")
    print(" -", out_benign, "| count =", len(benign))
    print(" -", out_mal, "| count =", len(malicious))
    print("Next:")
    print("  python -m src.prepare_data")
    print("  python -m src.train")
    print("  python -m src.evaluate")


if __name__ == "__main__":
    main()
