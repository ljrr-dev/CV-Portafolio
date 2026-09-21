"""Construye los datasets locales para la demo de triage de vulnerabilidades.

Fuentes publicas:
  KEV   - CISA Known Exploited Vulnerabilities
  EPSS  - FIRST Exploit Prediction Scoring System
  NVD   - mirror JSON de fkie-cad (CVSS + CWE por CVE)
  CAPEC - MITRE, puente CWE -> ATT&CK

Ejecutar a mano cuando se quieran refrescar los datos:
    python scripts/fetch_data.py
Deja CSV comprimidos en data/ ; demo.qmd solo los lee.
"""
import csv, gzip, io, json, lzma, os, re, sys, urllib.request, zipfile
from concurrent.futures import ThreadPoolExecutor

RAW = os.environ.get("RAW_DIR", "raw")
OUT = "data"
YEARS = range(1999, 2027)

KEV_URL   = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL  = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
CAPEC_URL = "https://capec.mitre.org/data/csv/1000.csv.zip"
NVD_URL   = ("https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/"
             "download/CVE-{year}.json.xz")


def grab(url, path):
    """Descarga url a path si aun no existe. Devuelve path."""
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "portfolio-demo"})
    with urllib.request.urlopen(req, timeout=180) as r, open(path, "wb") as f:
        f.write(r.read())
    return path


def cvss_of(item):
    """Score, severidad y vector de la mejor metrica CVSS disponible."""
    m = item.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = m.get(key)
        if entries:
            d = entries[0].get("cvssData", {})
            sev = d.get("baseSeverity") or entries[0].get("baseSeverity")
            return d.get("baseScore"), sev, d.get("attackVector") or d.get("accessVector")
    return None, None, None


def cwes_of(item):
    out = []
    for w in item.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-"):
                out.append(v)
    return sorted(set(out))


def build_cves():
    """NVD -> data/cves.csv.gz (una fila por CVE con CVSS y CWE)."""
    def one(year):
        p = grab(NVD_URL.format(year=year), f"{RAW}/CVE-{year}.json.xz")
        data = json.loads(lzma.open(p).read())
        items = data.get("cve_items", data)
        rows = []
        for it in items:
            score, sev, vector = cvss_of(it)
            if score is None:
                continue
            rows.append({
                "cve": it["id"],
                "year": year,
                "published": (it.get("published") or "")[:10],
                "cvss": score,
                "severity": sev,
                "attack_vector": vector,
                "cwes": ";".join(cwes_of(it)),
            })
        print(f"  {year}: {len(rows):>6} CVEs con CVSS", flush=True)
        return rows

    with ThreadPoolExecutor(max_workers=6) as ex:
        chunks = list(ex.map(one, YEARS))
    rows = [r for c in chunks for r in c]

    with gzip.open(f"{OUT}/cves.csv.gz", "wt", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return rows


def build_epss():
    """EPSS -> data/epss.csv.gz (cve, epss, percentile)."""
    p = grab(EPSS_URL, f"{RAW}/epss.csv.gz")
    with gzip.open(p, "rt", encoding="utf-8") as f:
        first = f.readline()
        model = re.search(r"model_version:([^,]+)", first)
        date = re.search(r"score_date:(\S+)", first)
        rows = list(csv.DictReader(f))
    with gzip.open(f"{OUT}/epss.csv.gz", "wt", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve", "epss", "percentile"])
        w.writeheader()
        w.writerows(rows)
    return rows, (model.group(1) if model else "?"), (date.group(1)[:10] if date else "?")


def build_kev():
    """KEV -> data/kev.csv.gz."""
    p = grab(KEV_URL, f"{RAW}/kev.json")
    cat = json.load(open(p, encoding="utf-8"))
    rows = []
    for v in cat["vulnerabilities"]:
        rows.append({
            "cve": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "due_date": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "cwes": ";".join(v.get("cwes") or []),
        })
    with gzip.open(f"{OUT}/kev.csv.gz", "wt", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    return rows, cat.get("catalogVersion", "?"), (cat.get("dateReleased") or "")[:10]


def build_capec():
    """CAPEC -> data/cwe_attack.csv.gz (puente CWE -> tecnica ATT&CK)."""
    p = grab(CAPEC_URL, f"{RAW}/capec.zip")
    z = zipfile.ZipFile(p)
    rows_in = list(csv.DictReader(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8")))
    id_col = [c for c in rows_in[0] if c and c.endswith("ID")][0]

    out = []
    for r in rows_in:
        techs = re.findall(
            r"TAXONOMY NAME:ATTACK:ENTRY ID:([0-9.]+):ENTRY NAME:([^:]+)",
            r.get("Taxonomy Mappings") or "")
        if not techs:
            continue
        cwes = re.findall(r"(\d+)", r.get("Related Weaknesses") or "")
        for tid, tname in techs:
            for cwe in cwes:
                out.append({
                    "cwe": f"CWE-{cwe}",
                    "capec": f"CAPEC-{r[id_col]}",
                    "capec_name": r["Name"],
                    "technique": f"T{tid}",
                    "technique_name": tname.strip(),
                    "likelihood": r.get("Likelihood Of Attack", ""),
                    "severity": r.get("Typical Severity", ""),
                })
    # deduplica pares (cwe, technique) conservando el primer CAPEC que los une
    seen, ded = set(), []
    for r in out:
        k = (r["cwe"], r["technique"])
        if k not in seen:
            seen.add(k)
            ded.append(r)
    with gzip.open(f"{OUT}/cwe_attack.csv.gz", "wt", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(ded[0].keys()))
        w.writeheader()
        w.writerows(ded)
    return ded


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    print("KEV...");   kev, kver, kdate = build_kev();   print(f"  {len(kev)} CVEs (catalogo {kver}, {kdate})")
    print("EPSS...");  epss, emodel, edate = build_epss(); print(f"  {len(epss)} CVEs (modelo {emodel}, {edate})")
    print("CAPEC..."); bridge = build_capec();           print(f"  {len(bridge)} pares CWE->ATT&CK")
    print("NVD (27 anios, puede tardar)...")
    cves = build_cves();                                  print(f"  {len(cves)} CVEs con CVSS")

    json.dump({"kev_version": kver, "kev_date": kdate,
               "epss_model": emodel, "epss_date": edate,
               "n_cves": len(cves), "n_kev": len(kev),
               "n_epss": len(epss), "n_bridge": len(bridge)},
              open(f"{OUT}/meta.json", "w"), indent=2)
    print("\nListo -> data/")
