"""
SentinelAI - Stage 09: Autonomous SOC Investigation Workflow
============================================================
Stateful reasoning workflow connecting real-time multi-tier ML flow verdicts
with the RAG threat intelligence knowledge base to synthesize automated incident
reports and containment playbooks.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import os

from intelligence.agent.tools import SentinelSecurityTools, get_security_tools
from intelligence.agent.llm_provider import LLMReasoningEngine, get_llm_reasoning_engine


class IncidentInvestigationWorkflow:
    """
    Autonomous SOC agent workflow that processes an incoming ML detection alert,
    correlates with MITRE ATT&CK, CISA KEV, and OWASP, and generates an
    executive incident response report with targeted mitigation steps.
    """
    def __init__(
        self,
        tools: Optional[SentinelSecurityTools] = None,
        llm_engine: Optional[LLMReasoningEngine] = None
    ):
        self.tools = tools or get_security_tools()
        self.llm_engine = llm_engine or get_llm_reasoning_engine()

    def determine_incident_severity(self, attack_family: str, confidence: float) -> str:
        """
        Computes dynamic incident severity based on attack category and model confidence.
        """
        critical_categories = ["DDoS", "Infiltration", "Botnet"]
        high_categories = ["Web Exploitation", "Brute Force", "DoS"]
        medium_categories = ["PortScan", "Fuzzing"]

        if attack_family in critical_categories:
            return "CRITICAL" if confidence >= 0.80 else "HIGH"
        elif attack_family in high_categories:
            return "HIGH" if confidence >= 0.70 else "MEDIUM"
        elif attack_family in medium_categories:
            return "MEDIUM"
        return "LOW"

    def determine_immediate_containment_action(self, attack_family: str, dst_port: Optional[int]) -> Dict[str, Any]:
        """
        Determines line-rate automated containment actions for firewalls / EDR agents.
        """
        action_matrix = {
            "DDoS": {
                "action": "RATE_LIMIT_AND_BGP_BLACKHOLE",
                "description": "Engage upstream scrubbing center, rate-limit ingress interfaces, and drop UDP/SYN floods."
            },
            "DoS": {
                "action": "DROP_CONNECTION_AND_THROTTLE",
                "description": "Terminate offending TCP connection and enforce per-IP concurrency connection limits."
            },
            "Infiltration": {
                "action": "QUARANTINE_HOST_AND_SEVER_SMB",
                "description": "Isolate host from internal VLAN; sever SMB/RPC sessions (ports 445/139) to halt lateral movement."
            },
            "Botnet": {
                "action": "BLOCK_C2_OUTBOUND_AND_DNS_SINKHOLE",
                "description": "Null-route outbound beaconing traffic and sinkhole malicious DNS domains at internal resolvers."
            },
            "Web Exploitation": {
                "action": "APPLY_WAF_BLOCK_AND_SESSION_REVOKE",
                "description": "Activate WAF inspection rules, terminate active session tokens, and block SQL/command injection vectors."
            },
            "Brute Force": {
                "action": "LOCK_ACCOUNT_AND_IP_BAN",
                "description": "Enforce 30-minute lockout on targeted credentials and ban attacker IP at edge firewall."
            },
            "PortScan": {
                "action": "TEMP_IP_REPUTATION_SHROUD",
                "description": "Flag scanning IP in threat telemetry table; feed decoy honeypot responses to disorient reconnaissance."
            },
            "Fuzzing": {
                "action": "DROP_MALFORMED_PACKET_AND_RESTART_DAEMON",
                "description": "Drop malformed non-RFC packets and verify process memory integrity for targeted service."
            }
        }

        default_action = {
            "action": "LOG_AND_MONITOR",
            "description": "Deepen flow inspection rate and capture pcap for forensic evaluation."
        }

        return action_matrix.get(attack_family, default_action)

    def investigate_alert(
        self,
        attack_family: str,
        confidence: float,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        decisive_features: Optional[List[str]] = None,
        anomaly_score: Optional[float] = None,
        llm_provider: Optional[str] = "deterministic",
        llm_model: Optional[str] = None,
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end SOC investigation on a detected network intrusion.
        Supports swappable reasoning providers: 'deterministic', 'ollama', 'gemini', 'openai'.
        """
        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        severity = self.determine_incident_severity(attack_family, confidence)
        containment = self.determine_immediate_containment_action(attack_family, dst_port)

        # 1. RAG Query for TTPs and Adversary Attribution
        rag_query = f"{attack_family} attack"
        if dst_port:
            rag_query += f" targeting port {dst_port}"
        if decisive_features:
            rag_query += f" exhibiting {', '.join(decisive_features[:2])}"

        ttp_hits = self.tools.search_threat_intel(rag_query, category=attack_family, top_k=2)

        # 2. RAG Query for Defenses & Mitigations
        mitigation_hits = self.tools.get_playbook_for_attack(attack_family, top_k=3)

        # 3. Assemble structured incident brief
        incident_report = {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "severity": severity,
            "verdict": "MALICIOUS" if attack_family != "Normal" else "BENIGN",
            "threat_family": attack_family,
            "confidence": round(confidence, 4),
            "flow_context": {
                "src_ip": src_ip or "N/A (Quarantined)",
                "dst_ip": dst_ip or "N/A (Internal Target)",
                "dst_port": dst_port,
                "anomaly_score": round(anomaly_score, 4) if anomaly_score is not None else None,
                "decisive_features": decisive_features or []
            },
            "immediate_containment": containment,
            "mitre_attribution": [
                {
                    "identifier": hit.get("identifier"),
                    "title": hit.get("title"),
                    "source": hit.get("source"),
                    "relevance_score": hit.get("score")
                }
                for hit in ttp_hits
            ],
            "recommended_playbooks": [
                {
                    "title": hit.get("title"),
                    "source": hit.get("source"),
                    "identifier": hit.get("identifier"),
                    "guidance": hit.get("text")[:350].replace("\n", " ") + "..."
                }
                for hit in mitigation_hits
            ]
        }

        # 4. Synthesize AI Reasoning via selected provider (Deterministic, Ollama, Gemini)
        reasoning = self.llm_engine.generate_reasoning(
            incident_context=incident_report,
            provider=llm_provider,
            model=llm_model,
            api_key=api_key
        )
        incident_report["reasoning"] = reasoning

        return incident_report


if __name__ == "__main__":
    workflow = IncidentInvestigationWorkflow()
    sample_alert = workflow.investigate_alert(
        attack_family="Infiltration",
        confidence=0.9842,
        src_ip="192.168.10.50",
        dst_ip="10.0.0.12",
        dst_port=445,
        decisive_features=["traffic_symmetry_ratio (+2.14)", "bwd_pkt_len_mean (-1.82)"],
        anomaly_score=0.0891
    )

    print("=" * 70)
    print("  AUTONOMOUS INCIDENT INVESTIGATION REPORT")
    print("=" * 70)
    print(f"Incident ID: {sample_alert['incident_id']}")
    print(f"Severity:    {sample_alert['severity']}")
    print(f"Category:    {sample_alert['threat_family']} ({sample_alert['confidence']*100:.2f}%)")
    print(f"Containment: {sample_alert['immediate_containment']['action']}")
    print(f"Action Desc: {sample_alert['immediate_containment']['description']}")
    print("\nMITRE TTP Attribution:")
    for att in sample_alert["mitre_attribution"]:
        print(f"  • {att['identifier']}: {att['title']} (Score: {att['relevance_score']})")
    print("\nDefensive Playbooks:")
    for pb in sample_alert["recommended_playbooks"]:
        print(f"  • [{pb['source'].upper()}] {pb['title']}")

