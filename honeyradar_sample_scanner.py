#!/usr/bin/env python3
"""
HoneyRadar malware sample scanner.

Watches Cowrie's downloads directory, computes hashes, scans files locally with
ClamAV/YARA, checks VirusTotal by SHA256, checks MalwareBazaar by SHA256, and
writes JSONL events for the HoneyRadar WebSocket bridge.
"""

import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


DOWNLOAD_DIR = Path(os.getenv("COWRIE_DOWNLOAD_DIR", "/home/cowrie/cowrie/var/lib/cowrie/downloads"))
OUTPUT_LOG = Path(os.getenv("HONEYRADAR_MALWARE_LOG", "/var/tmp/honeyradar-malware.log"))
STATE_FILE = Path(os.getenv("HONEYRADAR_MALWARE_STATE", "/var/tmp/honeyradar-malware-seen.json"))
YARA_RULES = Path(os.getenv("YARA_RULES", "/opt/honeyradar/yara"))
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "10"))
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
MALWAREBAZAAR_AUTH_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY", "").strip()


def load_seen() -> Dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def save_seen(seen: Dict[str, Any]) -> None:
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(seen, indent=2, sort_keys=True))
    tmp.replace(STATE_FILE)


def file_hashes(path: Path) -> Dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def run_command(cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {"returncode": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as exc:
        return {"returncode": -1, "stdout": "", "stderr": str(exc)}


def scan_clamav(path: Path) -> Dict[str, Any]:
    result = run_command(["clamscan", "--no-summary", str(path)], timeout=60)
    infected = result["returncode"] == 1
    signature = None

    if infected and "FOUND" in result["stdout"]:
        # Example: /path/file: Unix.Malware.Agent FOUND
        signature = result["stdout"].split(":", 1)[-1].replace("FOUND", "").strip()

    return {
        "enabled": result["returncode"] != -1,
        "infected": infected,
        "signature": signature,
        "raw": result["stdout"] or result["stderr"],
    }


def scan_yara(path: Path) -> Dict[str, Any]:
    if not YARA_RULES.exists():
        return {"enabled": False, "matches": []}

    result = run_command(["yara", "-r", str(YARA_RULES), str(path)], timeout=60)
    matches = []

    for line in result["stdout"].splitlines():
        parts = line.split(maxsplit=1)
        if parts:
            matches.append(parts[0])

    return {
        "enabled": True,
        "matches": sorted(set(matches)),
        "raw": result["stdout"] or result["stderr"],
    }


def http_json(url: str, headers: Dict[str, str] | None = None, timeout: int = 15) -> Any:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def http_post_form(url: str, data: Dict[str, str], headers: Dict[str, str] | None = None, timeout: int = 15) -> Any:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, headers=headers or {}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def check_virustotal(sha256: str) -> Dict[str, Any]:
    if not VT_API_KEY:
        return {"enabled": False}

    try:
        data = http_json(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
        )
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        names = attrs.get("names", [])

        return {
            "enabled": True,
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "type_description": attrs.get("type_description"),
            "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label"),
            "names": names[:10] if isinstance(names, list) else [],
        }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"enabled": True, "found": False}
        return {"enabled": True, "found": None, "error": f"HTTP {exc.code}"}
    except Exception as exc:
        return {"enabled": True, "found": None, "error": str(exc)}


def check_malwarebazaar(sha256: str) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if MALWAREBAZAAR_AUTH_KEY:
        headers["Auth-Key"] = MALWAREBAZAAR_AUTH_KEY

    try:
        data = http_post_form(
            "https://mb-api.abuse.ch/api/v1/",
            {"query": "get_info", "hash": sha256},
            headers=headers,
        )
        rows = data.get("data") if isinstance(data, dict) else []
        if not isinstance(rows, list):
            rows = []

        malware = set()
        tags = set()
        signatures = set()

        for row in rows:
            if not isinstance(row, dict):
                continue
            for key in ("signature", "malware", "file_type_mime"):
                if row.get(key):
                    signatures.add(str(row[key]))
            for key in ("malware_family", "malware_printable"):
                if row.get(key):
                    malware.add(str(row[key]))
            if isinstance(row.get("tags"), list):
                tags.update(str(t) for t in row["tags"] if t)

        return {
            "enabled": True,
            "found": len(rows) > 0,
            "matches": len(rows),
            "malware": sorted(malware),
            "signatures": sorted(signatures),
            "tags": sorted(tags),
        }
    except Exception as exc:
        return {"enabled": True, "found": None, "error": str(exc)}


def emit(event: Dict[str, Any]) -> None:
    OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")


def scan_file(path: Path) -> Dict[str, Any]:
    hashes = file_hashes(path)
    clamav = scan_clamav(path)
    yara = scan_yara(path)
    virustotal = check_virustotal(hashes["sha256"])
    malwarebazaar = check_malwarebazaar(hashes["sha256"])

    score = 0
    if clamav.get("infected"):
        score = max(score, 90)
    if yara.get("matches"):
        score = max(score, 70)
    if virustotal.get("malicious", 0) >= 5:
        score = max(score, 85)
    elif virustotal.get("malicious", 0) >= 1:
        score = max(score, 60)
    if malwarebazaar.get("found"):
        score = max(score, 80)

    malware_names = set()
    if virustotal.get("popular_threat_name"):
        malware_names.add(str(virustotal["popular_threat_name"]))
    malware_names.update(malwarebazaar.get("malware", []))
    malware_names.update(malwarebazaar.get("signatures", []))
    if clamav.get("signature"):
        malware_names.add(str(clamav["signature"]))

    return {
        "eventid": "honeyradar.malware.sample",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": "malware_scanner",
        "path": str(path),
        "filename": path.name,
        "size": path.stat().st_size,
        "hashes": hashes,
        "sha256": hashes["sha256"],
        "score": score,
        "malicious": score >= 70,
        "malware": ", ".join(sorted(malware_names)) if malware_names else None,
        "clamav": clamav,
        "yara": yara,
        "virustotal": virustotal,
        "malwarebazaar": malwarebazaar,
    }


def main() -> None:
    seen = load_seen()
    print(f"Watching {DOWNLOAD_DIR}", flush=True)

    while True:
        if not DOWNLOAD_DIR.exists():
            time.sleep(SCAN_INTERVAL)
            continue

        for path in DOWNLOAD_DIR.iterdir():
            if not path.is_file():
                continue

            try:
                st = path.stat()
                marker = f"{st.st_size}:{int(st.st_mtime)}"
                key = str(path)
                if seen.get(key) == marker:
                    continue

                event = scan_file(path)
                emit(event)
                seen[key] = marker
                save_seen(seen)
                print(f"Scanned {path.name} sha256={event['sha256']} score={event['score']}", flush=True)
            except Exception as exc:
                print(f"Failed scanning {path}: {exc}", flush=True)

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
