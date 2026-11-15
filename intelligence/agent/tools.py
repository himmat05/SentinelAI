"""
SentinelAI - Stage 09: Autonomous SOC Investigation Tools
=========================================================
Custom security tools bridging machine learning flow verdicts (Stage 06-08)
with the RAG threat intelligence knowledge base (Stage 09).
"""

from typing import List, Dict, Any, Optional
import os
import re

from intelligence.rag.retrieval import ThreatIntelRetriever


class SentinelSecurityTools:
    """
    Toolkit used by the autonomous SOC reasoning agent to cross-examine
    real-time network intrusion alerts with threat intelligence feeds.
    """
    def __init__(self, retriever: Optional[ThreatIntelRetriever] = None):
        self._retriever = retriever

    @property
    def retriever(self) -> ThreatIntelRetriever:
        if self._retriever is None:
            self._retriever = ThreatIntelRetriever()
        return self._retriever

    def search_threat_intel(
        self,
        query: str,
        category: Optional[str] = None,
        source: Optional[str] = None,
        top_k: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Performs semantic similarity search over the unified vector database.
        """
        return self.retriever.search(
            query=query,
            n_results=top_k,
            category=category,
            source=source
        )

    def lookup_mitre_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Exact lookup for a MITRE ATT&CK technique by ID (e.g., 'T1059' or 'T1055.011').
        """
        # Search by identifier in ChromaDB
        clean_id = technique_id.strip().upper()
        results = self.retriever.search(clean_id, n_results=5, source="mitre_attack")
        for hit in results:
            if hit.get("identifier", "").upper().startswith(clean_id):
                return hit
        return results[0] if results else None

    def check_cve_weaponization(self, cve_id: str) -> Dict[str, Any]:
        """
        Checks CISA KEV to determine if a CVE is actively exploited in the wild,
        its ransomware campaign association, and federal mitigation deadlines.
        """
        clean_cve = cve_id.strip().upper()
        results = self.retriever.search(clean_cve, n_results=3, source="cisa_kev")

        for hit in results:
            if hit.get("identifier", "").upper() == clean_cve:
                meta = hit.get("metadata", {})
                return {
                    "is_weaponized": True,
                    "cve_id": clean_cve,
                    "title": hit.get("title"),
                    "ransomware_association": meta.get("ransomware_use", False),
                    "vendor": meta.get("vendor"),
                    "product": meta.get("product"),
                    "due_date": meta.get("due_date"),
                    "required_action": meta.get("required_action"),
                    "details": hit.get("text")
                }

        return {
            "is_weaponized": False,
            "cve_id": clean_cve,
            "status": "Not currently cataloged in CISA Known Exploited Vulnerabilities."
        }

    def get_playbook_for_attack(self, attack_family: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Retrieves recommended SOC containment playbooks, OWASP defenses, and
        MITRE course-of-action mitigations for a specific detected attack family.
        """
        return self.retriever.get_mitigations_for_alert(attack_family, top_k=top_k)

    def formulate_incident_brief(
        self,
        attack_family: str,
        confidence: float,
        src_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        top_decisive_factors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Combines machine learning verdict, explainable SHAP drivers, and
        retrieved RAG intelligence into an executive incident brief.
        """
        query_context = f"{attack_family} intrusion on port {dst_port}" if dst_port else attack_family
        if top_decisive_factors:
            query_context += f" driven by {' '.join(top_decisive_factors[:2])}"

        # 1. Retrieve top matching TTPs and playbooks
        threat_hits = self.search_threat_intel(query_context, category=attack_family, top_k=2)
        mitigation_hits = self.get_playbook_for_attack(attack_family, top_k=2)

        # 2. Formulate executive action recommendations
        recommended_actions = []
        for m in mitigation_hits:
            title = m.get("title", "Remediation Guide")
            source = m.get("source", "").upper()
            recommended_actions.append(f"[{source}] {title}")

        return {
            "verdict": "MALICIOUS" if attack_family != "Normal" else "BENIGN",
            "threat_family": attack_family,
            "confidence": round(confidence, 4),
            "threat_attribution": [
                {
                    "identifier": h.get("identifier"),
                    "title": h.get("title"),
                    "source": h.get("source"),
                    "score": h.get("score")
                }
                for h in threat_hits
            ],
            "autonomous_playbooks": recommended_actions,
            "soc_summary": (
                f"SentinelAI multi-tier engine intercepted a {attack_family} attack "
                f"with {confidence*100:.1f}% confidence. Correlated with {len(threat_hits)} "
                f"authoritative intelligence sources."
            )
        }


# Singleton accessor
_tools_instance: Optional[SentinelSecurityTools] = None

def get_security_tools() -> SentinelSecurityTools:
    global _tools_instance
    if _tools_instance is None:
        _tools_instance = SentinelSecurityTools()
    return _tools_instance

