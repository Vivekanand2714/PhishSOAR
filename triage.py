"""
Triage Decision Engine
=======================
Scores and classifies phishing emails based on IoC enrichment results.
Produces a final verdict: MALICIOUS / SUSPICIOUS / CLEAN

Person 3-4 Role: Automated triage
MITRE ATT&CK: T1566, T1598
"""

import logging
from typing import Dict, Any
from config import MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, MITRE_MAPPING

logger = logging.getLogger(__name__)


def triage(iocs: dict, enrichment: dict) -> Dict[str, Any]:
    """
    Run triage on extracted IoCs and enrichment results.
    Returns verdict with score, reasons, and MITRE ATT&CK mappings.
    """
    logger.info("Running triage decision engine...")

    score         = 0
    reasons       = []
    mitre_tags    = []
    attack_types  = []

    # ── 1. Enrichment-based scoring ──────────────────────────
    vt_malicious_count = 0
    vt_suspicious_count = 0

    for url_result in enrichment.get("url_results", []):
        vt = url_result.get("virustotal", {})
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)
        vt_malicious_count  += mal
        vt_suspicious_count += sus

        if mal >= MALICIOUS_THRESHOLD:
            score += 40
            reasons.append(f"URL flagged malicious by {mal} VT vendors: {url_result['url'][:60]}")
        elif mal > 0:
            score += 20
            reasons.append(f"URL flagged by {mal} VT vendor(s): {url_result['url'][:60]}")
        elif sus > 0:
            score += 10
            reasons.append(f"URL flagged suspicious by {sus} VT vendor(s): {url_result['url'][:60]}")

        # URLScan verdict
        urlscan = url_result.get("urlscan", {})
        if urlscan.get("malicious"):
            score += 30
            reasons.append(f"URLScan flagged URL as malicious (score: {urlscan.get('score', 0)})")
            if urlscan.get("brands"):
                reasons.append(f"URLScan detected brand impersonation: {', '.join(urlscan['brands'])}")
                attack_types.append("spear_phishing")

    for domain_result in enrichment.get("domain_results", []):
        vt = domain_result.get("virustotal", {})
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)

        if mal >= MALICIOUS_THRESHOLD:
            score += 35
            reasons.append(f"Domain flagged malicious by {mal} VT vendors: {domain_result['domain']}")
        elif mal > 0:
            score += 15
            reasons.append(f"Domain flagged by {mal} VT vendor(s): {domain_result['domain']}")
        elif sus > 0:
            score += 8
            reasons.append(f"Domain flagged suspicious: {domain_result['domain']}")

    # ── 2. IoC-based scoring ──────────────────────────────────
    risk_indicators = iocs.get("risk_indicators", [])
    for indicator in risk_indicators:
        score += 10
        reasons.append(f"Risk indicator: {indicator}")

    header_anomalies = iocs.get("header_anomalies", [])
    for anomaly in header_anomalies:
        score += 5
        reasons.append(f"Header anomaly: {anomaly}")

    # Keyword density
    keywords = iocs.get("keywords_found", [])
    if len(keywords) >= 5:
        score += 20
        reasons.append(f"High phishing keyword density: {len(keywords)} keywords")
        attack_types.append("phishing")
    elif len(keywords) >= 2:
        score += 10
        reasons.append(f"Moderate keyword count: {len(keywords)} phishing keywords")

    # Suspicious attachments
    suspicious_attachments = [a for a in iocs.get("attachments", []) if a.get("suspicious")]
    if suspicious_attachments:
        score += 25
        fnames = [a["filename"] for a in suspicious_attachments]
        reasons.append(f"Suspicious attachments: {', '.join(fnames)}")
        attack_types.append("spear_phishing")

    # ── 3. Sender domain trust scoring ────────────────────────
    sender_trust = enrichment.get("sender_trust")
    if sender_trust:
        trust_score = sender_trust.get("trust_score", 100)
        trust_level = sender_trust.get("trust_level", "TRUSTED")
        risk_flags = sender_trust.get("risk_flags", [])

        if trust_level != "TRUSTED":
            reasons.append(f"Sender domain authenticity is {trust_level} (Trust Score: {trust_score}/100)")
            if trust_level == "SPOOFED":
                score += 45
                attack_types.append("phishing")
            elif trust_level == "UNTRUSTED":
                score += 30
            elif trust_level == "SUSPICIOUS":
                score += 15

        for flag in risk_flags:
            reasons.append(f"Sender Auth Flag: {flag}")

    # ── 4. Determine verdict ──────────────────────────────────
    score = min(score, 100)  # Cap at 100

    if score >= 60:
        verdict = "MALICIOUS"
        action  = "QUARANTINE + BLOCK"
        color   = "#ef4444"
        attack_types.append("phishing")
    elif score >= 30:
        verdict = "SUSPICIOUS"
        action  = "QUARANTINE + ANALYST REVIEW"
        color   = "#f59e0b"
        attack_types.append("info_gathering")
    else:
        verdict = "CLEAN"
        action  = "NO ACTION"
        color   = "#10b981"

    # ── 4. MITRE ATT&CK mappings ──────────────────────────────
    if not attack_types:
        attack_types = ["phishing"]

    for attack_type in set(attack_types):
        if attack_type in MITRE_MAPPING:
            mitre_tags.append(MITRE_MAPPING[attack_type])

    # Always include base phishing technique
    if MITRE_MAPPING["phishing"] not in mitre_tags:
        mitre_tags.append(MITRE_MAPPING["phishing"])

    result = {
        "verdict":      verdict,
        "score":        score,
        "action":       action,
        "color":        color,
        "reasons":      reasons,
        "mitre_tags":   mitre_tags,
        "attack_types": list(set(attack_types)),
        "stats": {
            "vt_malicious":   vt_malicious_count,
            "vt_suspicious":  vt_suspicious_count,
            "risk_indicators": len(risk_indicators),
            "keywords":       len(keywords),
            "suspicious_attachments": len(suspicious_attachments),
        }
    }

    logger.info(
        f"Triage complete — Verdict: {verdict} | Score: {score}/100 | "
        f"Reasons: {len(reasons)}"
    )
    return result
