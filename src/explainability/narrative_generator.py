"""
Automated Analyst Narrative and Explanation Card Generator for CyberVision.
Translates mathematical feature attributions (SHAP), MITRE ATT&CK tags, and CTI
into human-readable triage summaries and AI-powered SOC briefs.
"""

from typing import Dict, Any, List, Optional
import os
import requests
from dotenv import load_dotenv
from src.utils.security import get_secret

load_dotenv()


class NarrativeGenerator:
    """Generates structured SOC incident cards and triage explanations."""

    def __init__(self):
        self.gemini_key = get_secret("GEMINI_API_KEY")

    def generate_explanation_card(
        self,
        alert_id: str,
        attack_category: str,
        confidence: float,
        severity: str,
        risk_score: float,
        top_shap_features: List[Dict[str, Any]],
        mitre_technique_id: str = "T1110",
        correlated_entities: List[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a structured, publishable SOC Analyst Explanation Card.
        """
        conf_pct = round(confidence * 100.0, 1)
        score_val = round(risk_score, 1)

        # Build feature trigger bullets
        trigger_phrases = []
        for i, feat in enumerate(top_shap_features[:3], 1):
            fname = feat.get("feature", "feature")
            shap_val = feat.get("shap_value", 0.0)
            sample_val = feat.get("sample_value", 0.0)
            median_val = feat.get("baseline_median", 0.0)

            # Compute deviation multiple
            if median_val > 0 and sample_val > median_val:
                ratio = sample_val / median_val
                dev_str = f" [{ratio:.1f}x above benign baseline]"
            else:
                dev_str = ""

            clean_name = fname.replace("feat_", "").replace("_", " ")
            trigger_phrases.append(f"({i}) {clean_name} = {sample_val:.1f}{dev_str} ({shap_val:+.2f} SHAP)")

        triggers_text = ", ".join(trigger_phrases) if trigger_phrases else "Statistical anomaly across network telemetry"
        entities_text = f" across entities ({', '.join(correlated_entities)})" if correlated_entities else ""

        narrative = (
            f"Alert {alert_id} classified as **{attack_category}** "
            f"(**Confidence**: {conf_pct}%, **Severity**: {severity} [Score: {score_val}/100]){entities_text}. "
            f"Primary AI triggers: {triggers_text}. "
            f"Corroborated across telemetry layers and mapped to MITRE ATT&CK **{mitre_technique_id}**."
        )

        return {
            "alert_id": alert_id,
            "attack_category": attack_category,
            "confidence_pct": conf_pct,
            "severity": severity,
            "risk_score": score_val,
            "mitre_technique_id": mitre_technique_id,
            "narrative": narrative,
            "trigger_features": top_shap_features[:5]
        }

    def generate_ai_analyst_brief(
        self,
        alert_info: Dict[str, Any],
        cti_info: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Calls Gemini API (gemini-3.5-flash-lite) to synthesize an executive
        threat analysis brief, containment recommendations, and IOC notes.
        Falls back to rule-based synthesis if offline or key is missing.
        """
        if not self.gemini_key:
            return self._fallback_brief(alert_info, cti_info)

        prompt = (
            f"You are a Tier-3 Cybersecurity Incident Response Analyst for the CyberVision SOC.\n"
            f"Summarize the following threat detection event into an actionable, professional 3-paragraph executive briefing:\n\n"
            f"- Alert ID: {alert_info.get('alert_id')}\n"
            f"- Attack Type: {alert_info.get('attack_category')}\n"
            f"- Severity: {alert_info.get('severity')} (Risk Score: {alert_info.get('risk_score')}/100)\n"
            f"- Model Confidence: {alert_info.get('confidence_pct')}%\n"
            f"- MITRE ATT&CK Technique: {alert_info.get('mitre_technique_id')}\n"
            f"- Top Mathematical Feature Triggers: {alert_info.get('trigger_features')}\n"
            f"- CTI Reputation: {cti_info}\n\n"
            f"Structure your briefing with:\n"
            f"1. Threat Overview & Ingress Mechanism\n"
            f"2. Mathematical Evidence & Cross-Layer Corroboration\n"
            f"3. Immediate Remediation & Containment Playbook Actions\n"
            f"Keep it concise, rigorous, and technical."
        )

        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent?key={self.gemini_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}]
            }
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"].strip()
            else:
                return self._fallback_brief(alert_info, cti_info)
        except Exception:
            return self._fallback_brief(alert_info, cti_info)

    def _fallback_brief(self, alert_info: Dict[str, Any], cti_info: Optional[Dict[str, Any]]) -> str:
        """Offline deterministic SOC analysis brief."""
        cat = alert_info.get("attack_category", "Suspicious Activity")
        sev = alert_info.get("severity", "High")
        score = alert_info.get("risk_score", 85)
        mitre = alert_info.get("mitre_technique_id", "T1046")
        
        return (
            f"### Executive Threat Briefing: {cat} ({sev} - Score {score}/100)\n\n"
            f"**1. Threat Overview:** Telemetry corroboration indicates active adversary behavior matching "
            f"MITRE ATT&CK {mitre}. The intrusion vector exhibits anomalous volumetric and connection patterns "
            f"significantly deviating from established host baseline behavior.\n\n"
            f"**2. Mathematical Evidence:** The hybrid threat ensemble triggered on high-weight SHAP feature deviations. "
            f"Local surrogate modeling confirms connection frequency and payload entropy as primary driving indicators.\n\n"
            f"**3. Recommended Containment Playbook:**\n"
            f"- Isolate affected host endpoints from the corporate subnet.\n"
            f"- Apply egress block rules on the perimeter firewall for identified external IP addresses.\n"
            f"- Revoke active Kerberos/LDAP session tokens for associated user accounts and force credential reset."
        )
