"""
Alert parsing and input normalisation.

Everything the user supplies (Wazuh JSON, a pasted log line, a text/log file, or fields read from
an image) is converted into ONE Wazuh-style alert dictionary, so the analysis pipeline never has
to care where the alert came from.

Nothing here is invented: values that are not present stay empty / None, and anything guessed by
a pattern is flagged as a heuristic so the analyst can confirm it.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

MAX_TEXT_CHARS = 20000

# SERC display bands (these are SERC's own labels, not an official Wazuh scale)
SEVERITY_BANDS = [(3, "Low"), (7, "Medium"), (11, "High"), (15, "Critical")]

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def severity_label(level: Optional[int]) -> str:
    if level is None:
        return "Unknown"
    for upper, label in SEVERITY_BANDS:
        if level <= upper:
            return label
    return "Critical"


def _as_list(value: Any) -> List[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- view of an alert
def view_of(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Flat, display-friendly view of a Wazuh-style alert."""
    rule = alert.get("rule") or {}
    mitre = rule.get("mitre") or {}
    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    level = _to_int(rule.get("level"))
    compliance = {
        k.upper().replace("_", " "): _as_list(rule.get(k))
        for k in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13")
        if rule.get(k)
    }
    full_log = str(alert.get("full_log") or "")
    win = (data.get("win") or {}).get("eventdata") if isinstance(data.get("win"), dict) else None
    win = win if isinstance(win, dict) else {}
    srcuser = str(data.get("srcuser") or data.get("dstuser") or win.get("targetUserName") or "")
    fingerprint = hashlib.sha1(json.dumps(alert, sort_keys=True, default=str).encode()).hexdigest()[:10]
    return {
        "alert_id": str(alert.get("id") or f"alert-{fingerprint}"),
        "timestamp": str(alert.get("timestamp") or ""),
        "rule_id": str(rule.get("id") or ""),
        "level": level,
        "severity": severity_label(level),
        "description": str(rule.get("description") or "").strip() or full_log[:120],
        "groups": _as_list(rule.get("groups")),
        "agent_name": str(agent.get("name") or ""),
        "agent_ip": str(agent.get("ip") or ""),
        "srcip": str(data.get("srcip") or ""),
        "srcuser": srcuser,
        "full_log": full_log,
        "location": str(alert.get("location") or ""),
        "mitre_ids": _as_list(mitre.get("id")),
        "mitre_tactics": _as_list(mitre.get("tactic")),
        "mitre_techniques": _as_list(mitre.get("technique")),
        "mitre_source": str((alert.get("_serc") or {}).get("mitre_source") or "wazuh_rule"),
        "compliance": compliance,
    }


def validate_alert(alert: Any) -> Tuple[bool, List[str], List[str]]:
    errors, warnings = [], []
    if not isinstance(alert, dict):
        return False, ["The alert must be a JSON object."], warnings
    rule = alert.get("rule")
    if not isinstance(rule, dict) and not alert.get("full_log"):
        errors.append("No 'rule' section and no 'full_log' found. SERC needs at least one of them.")
    else:
        if isinstance(rule, dict) and not rule.get("description") and not alert.get("full_log"):
            errors.append("The rule has no description and there is no full_log to read.")
        if isinstance(rule, dict) and rule.get("level") is None:
            warnings.append("No severity level (rule.level) was provided, so severity is shown as Unknown.")
        if isinstance(rule, dict) and not (rule.get("mitre") or {}).get("id"):
            warnings.append("The alert carries no MITRE ATT&CK technique ID. SERC will rely on semantic search only.")
    return (not errors), errors, warnings


def searchable_text(alert: Dict[str, Any]) -> str:
    """Every value in the alert as plain text (not JSON-escaped), so quotes and backslashes in logs still match."""
    out: List[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
        elif v is not None:
            out.append(str(v))

    walk(alert)
    return "\n".join(out)


# --------------------------------------------------------------------------- raw logs
# (regex, description, technique id, tactic, technique name). Suggestions only: flagged as heuristic.
LOG_PATTERNS = [
    (re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?: port (?P<port>\d+))?", re.I),
     "sshd: authentication failed", "T1110", "Credential Access", "Brute Force"),
    (re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})", re.I),
     "sshd: authentication succeeded", "T1078", "Initial Access", "Valid Accounts"),
    (re.compile(r"(?:EventID|Event ID)\D{0,5}4625\b", re.I),
     "Windows: failed logon attempt", "T1110", "Credential Access", "Brute Force"),
    (re.compile(r"sudo:.*COMMAND=", re.I),
     "sudo command executed", "T1548.003", "Privilege Escalation", "Sudo and Sudo Caching"),
    (re.compile(r"powershell.*(?:-enc\b|-encodedcommand)", re.I),
     "Encoded PowerShell command", "T1059.001", "Execution", "PowerShell"),
    (re.compile(r"mimikatz|sekurlsa", re.I),
     "Possible credential dumping tool", "T1003.001", "Credential Access", "LSASS Memory"),
    (re.compile(r"\.(?:locked|crypt|encrypted)\b|ransom", re.I),
     "Possible ransomware activity", "T1486", "Impact", "Data Encrypted for Impact"),
]
SYSLOG_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+")


def alert_from_text(text: str, source_type: str = "raw_text") -> Dict[str, Any]:
    text = text.strip()[:MAX_TEXT_CHARS]
    first_line = next((l for l in text.splitlines() if l.strip()), text)
    desc, mitre_id, tactic, tech = "", "", "", ""
    user, srcip, port = "", "", ""
    for rx, d, tid, tac, tname in LOG_PATTERNS:
        m = rx.search(text)
        if m:
            desc, mitre_id, tactic, tech = d, tid, tac, tname
            gd = m.groupdict()
            user, srcip, port = gd.get("user") or "", gd.get("ip") or "", gd.get("port") or ""
            break
    if not srcip:
        m = IP_RE.search(text)
        srcip = m.group(0) if m else ""
    if not desc:
        desc = first_line[:140]
    host_m = SYSLOG_RE.match(first_line)
    fingerprint = hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:10]
    alert: Dict[str, Any] = {
        "id": f"user-{fingerprint}",
        "timestamp": host_m.group("ts") if host_m else "",
        "rule": {"id": "", "level": None, "description": desc, "groups": ["user_supplied"]},
        "agent": {"name": host_m.group("host") if host_m else "", "ip": ""},
        "full_log": text,
        "data": {k: v for k, v in (("srcip", srcip), ("srcuser", user), ("srcport", port)) if v},
        "location": "user_supplied",
        "_serc": {"source_type": source_type},
    }
    if mitre_id:
        alert["rule"]["mitre"] = {"id": [mitre_id], "tactic": [tactic], "technique": [tech]}
        alert["_serc"]["mitre_source"] = "heuristic_pattern"
    return alert


def alert_from_fields(fields: Dict[str, Any], source_type: str = "image") -> Dict[str, Any]:
    """Build an alert from fields read from an image. Missing fields stay empty."""
    def s(key: str) -> str:
        v = fields.get(key)
        return "" if v is None else str(v).strip()

    mitre_ids = [m for m in _as_list(fields.get("mitre_ids")) if re.fullmatch(r"T\d{4}(\.\d{3})?", m)]
    full_log = s("full_log")
    alert = {
        "id": f"{source_type}-{hashlib.sha1(json.dumps(fields, sort_keys=True, default=str).encode()).hexdigest()[:10]}",
        "timestamp": s("timestamp"),
        "rule": {"id": s("rule_id"), "level": _to_int(fields.get("level")),
                 "description": s("description") or full_log[:140], "groups": [f"from_{source_type}"]},
        "agent": {"name": s("agent_name"), "ip": s("agent_ip")},
        "full_log": full_log,
        "data": {k: v for k, v in (("srcip", s("srcip")), ("srcuser", s("user"))) if v},
        "location": f"user_supplied_{source_type}",
        "_serc": {"source_type": source_type},
    }
    if mitre_ids:
        alert["rule"]["mitre"] = {"id": mitre_ids}
        alert["_serc"]["mitre_source"] = "read_from_image"
    return alert


# --------------------------------------------------------------------------- top-level input handling
def _unwrap_json(obj: Any, warnings: List[str]) -> Optional[Dict[str, Any]]:
    if isinstance(obj, list):
        dicts = [o for o in obj if isinstance(o, dict)]
        if not dicts:
            return None
        if len(dicts) > 1:
            warnings.append(f"The file contains {len(dicts)} alerts. SERC analyses one at a time, so the first is loaded.")
        obj = dicts[0]
    if not isinstance(obj, dict):
        return None
    hits = (obj.get("hits") or {}).get("hits") if isinstance(obj.get("hits"), dict) else None
    if hits:
        obj = hits[0]
    if isinstance(obj.get("_source"), dict):
        obj = obj["_source"]
    if isinstance(obj.get("alert"), dict) and "rule" in obj["alert"]:
        obj = obj["alert"]
    return obj


def _extracted_fields(alert: Dict[str, Any], heuristic: bool = False) -> List[Dict[str, str]]:
    v = view_of(alert)
    origin_log = "guessed from the log text" if heuristic else "from the alert"
    rows = [
        ("Description", v["description"], origin_log),
        ("Severity level", "" if v["level"] is None else str(v["level"]),
         "from the alert" if v["level"] is not None else "not provided"),
        ("Agent / host", v["agent_name"], origin_log),
        ("Source IP", v["srcip"], origin_log),
        ("User", v["srcuser"], origin_log),
        ("MITRE technique", ", ".join(v["mitre_ids"]),
         ("suggested by a pattern, please confirm" if v["mitre_source"] == "heuristic_pattern" else "from the alert rule")),
    ]
    return [{"field": f, "value": val, "origin": o} for f, val, o in rows if val or f in ("Description", "Severity level")]


def parse_input(text: Optional[str], filename: str = "") -> Dict[str, Any]:
    """Pasted text or file text -> normalised alert plus what was extracted."""
    warnings: List[str] = []
    text = (text or "").strip()
    if not text:
        return {"ok": False, "message": "Nothing to read. Paste an alert or choose a file."}
    if len(text) > MAX_TEXT_CHARS:
        warnings.append(f"The input is long, so only the first {MAX_TEXT_CHARS:,} characters are used.")
        text = text[:MAX_TEXT_CHARS]

    parsed: Any = None
    if text[0] in "{[":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            rows = []
            for line in text.splitlines():  # newline-delimited JSON
                line = line.strip()
                if line.startswith("{"):
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
            parsed = rows or None
            if parsed is None:
                warnings.append("This looks like JSON but could not be parsed (check for a missing bracket or comma). It is treated as plain log text.")

    if parsed is not None:
        alert = _unwrap_json(parsed, warnings)
        if alert is not None and (isinstance(alert.get("rule"), dict) or alert.get("full_log")):
            ok, errors, warns = validate_alert(alert)
            if ok:
                warnings.extend(warns)
                return {"ok": True, "source_type": "wazuh_json", "alert": alert,
                        "extracted": _extracted_fields(alert), "warnings": warnings, "needs_confirmation": False}
            warnings.extend(errors)
        warnings.append("The JSON does not look like a Wazuh alert, so it is treated as plain log text.")

    lines = [l for l in text.splitlines() if l.strip()]
    if len(lines) > 25:
        warnings.append(f"{len(lines)} log lines found. They are analysed together as one incident (first 25 lines).")
        text = "\n".join(lines[:25])
    elif len(lines) > 1:
        warnings.append(f"{len(lines)} log lines found. They are analysed together as one incident.")
    source = "log_file" if filename else "raw_text"
    alert = alert_from_text(text, source_type=source)
    warnings.append("No severity level or rule ID in plain text: severity is shown as Unknown unless you enter one.")
    return {"ok": True, "source_type": source, "alert": alert,
            "extracted": _extracted_fields(alert, heuristic=True), "warnings": warnings, "needs_confirmation": True}


# --------------------------------------------------------------------------- guided form (analyst-friendly input)
FORM_SEVERITY_LEVELS = {"low": 3, "medium": 6, "high": 10, "critical": 13}   # a typical level for each SERC band
_TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def alert_from_form(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Build an alert from the guided form. Returns the same shape as ``parse_input``, or
    ``{"ok": False, "errors": {field: message}, "message": ...}`` when something cannot be used.
    Nothing is guessed: empty boxes stay empty."""
    def s(key: str, limit: int = 300) -> str:
        v = fields.get(key)
        return "" if v is None else str(v).strip()[:limit]

    errors: Dict[str, str] = {}
    warnings: List[str] = []

    description, full_log = s("description", 300), s("full_log", MAX_TEXT_CHARS)
    if not description and not full_log:
        errors["description"] = "Describe what happened, or paste the log line below."

    # severity: a band name or a number 0-15
    raw_level, level = s("level", 10).lower(), None
    if raw_level:
        if raw_level in FORM_SEVERITY_LEVELS:
            level = FORM_SEVERITY_LEVELS[raw_level]
        elif raw_level.isdigit() and 0 <= int(raw_level) <= 15:
            level = int(raw_level)
        else:
            errors["level"] = "Choose a severity, or enter a number from 0 to 15."
    else:
        warnings.append("No severity was chosen, so it is shown as Unknown.")

    srcip = s("srcip", 64)
    if srcip:
        try:
            srcip = str(ipaddress.ip_address(srcip))
        except ValueError:
            errors["srcip"] = "That is not a valid IP address (for example 203.0.113.7)."

    mitre_ids: List[str] = []
    for token in re.split(r"[\s,;]+", s("mitre", 200).upper()):
        if not token:
            continue
        if _TECHNIQUE_RE.fullmatch(token):
            if token not in mitre_ids:
                mitre_ids.append(token)
        else:
            errors["mitre"] = f"'{token}' is not an ATT&CK technique ID. Use a form like T1110 or T1110.001."
            break

    rule_id = s("rule_id", 60)
    if rule_id and not rule_id.isdigit():
        warnings.append("Wazuh rule IDs are normally numbers. It was kept as typed.")

    timestamp = s("timestamp", 40)
    if timestamp:
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            timestamp = (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        except ValueError:
            errors["timestamp"] = "That date and time could not be read."
    else:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+0000")

    if errors:
        return {"ok": False, "errors": errors, "message": "Please fix the highlighted fields."}

    desc = description or full_log.splitlines()[0][:140]
    key = json.dumps([desc, full_log, level, srcip, s("agent_name"), s("user"), mitre_ids, rule_id, timestamp], sort_keys=True)
    alert: Dict[str, Any] = {
        "id": f"form-{hashlib.sha1(key.encode('utf-8', 'ignore')).hexdigest()[:10]}",
        "timestamp": timestamp,
        "rule": {"id": rule_id, "level": level, "description": desc, "groups": ["from_form"]},
        "agent": {"name": s("agent_name", 120), "ip": ""},
        "full_log": full_log,
        "data": {k: v for k, v in (("srcip", srcip), ("srcuser", s("user", 120))) if v},
        "location": "user_supplied_form",
        "_serc": {"source_type": "form"},
    }
    if mitre_ids:
        alert["rule"]["mitre"] = {"id": mitre_ids}
        alert["_serc"]["mitre_source"] = "entered_by_analyst"
    ok, errs, warns = validate_alert(alert)
    warnings += [w for w in warns if w not in warnings and "No severity level" not in w]
    return {"ok": True, "source_type": "form", "alert": alert, "extracted": _extracted_fields(alert), "warnings": warnings,
            "needs_confirmation": True}


# Starting points for the form. They only pre-fill the boxes; the analyst edits everything before analysing.
FORM_TEMPLATES: List[Dict[str, Any]] = [
    {"key": "ssh_bruteforce", "label": "SSH brute force", "fields": {"description": "Multiple failed SSH logins from one source address", "level": "high", "mitre": "T1110", "full_log": "sshd[1042]: Failed password for invalid user admin from 203.0.113.50 port 54321 ssh2"}},
    {"key": "malware", "label": "Malware detected", "fields": {"description": "Antivirus detected malware on an endpoint", "level": "high", "mitre": "T1204"}},
    {"key": "phishing", "label": "Phishing email", "fields": {"description": "User reported a suspicious email asking for credentials", "level": "medium", "mitre": "T1566"}},
    {"key": "priv_esc", "label": "Privilege escalation", "fields": {"description": "A user gained administrator or root rights unexpectedly", "level": "critical", "mitre": "T1548"}},
    {"key": "log_cleared", "label": "Audit log cleared", "fields": {"description": "The audit log was cleared on a server", "level": "high", "mitre": "T1070"}},
    {"key": "port_scan", "label": "Port scan", "fields": {"description": "Many connection attempts to different ports from one source", "level": "medium", "mitre": "T1046"}},
]
