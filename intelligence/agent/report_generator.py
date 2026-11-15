"""
SentinelAI - Stage 09: Autonomous Incident Report Generator
===========================================================
Formats structured incident investigation telemetry into human-readable,
actionable executive Markdown briefs and automated SOC mitigation playbooks.
"""

from typing import Dict, Any, Optional
from pathlib import Path
import json
import os


class IncidentReportGenerator:
    """
    Renders high-fidelity SOC incident reports formatted with Markdown,
    severity tags, containment actions, and MITRE/OWASP defensive checklists.
    """
    def __init__(self, output_dir: Optional[Path] = None):
        if output_dir is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            self.output_dir = project_root / "intelligence" / "reports"
        else:
            self.output_dir = Path(output_dir)

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_markdown(self, incident: Dict[str, Any]) -> str:
        """
        Renders an executive security incident report in Markdown.
        """
        sev = incident.get("severity", "MEDIUM")
        sev_icon = "🔴" if sev == "CRITICAL" else ("🟠" if sev == "HIGH" else "🟡")
        verdict = incident.get("verdict", "MALICIOUS")
        family = incident.get("threat_family", "Unknown")
        confidence = incident.get("confidence", 0.0) * 100.0
        incident_id = incident.get("incident_id", "INC-UNKNOWN")
        timestamp = incident.get("timestamp", "N/A")

        flow = incident.get("flow_context", {})
        containment = incident.get("immediate_containment", {})
        attributions = incident.get("mitre_attribution", [])
        playbooks = incident.get("recommended_playbooks", [])
        reasoning = incident.get("reasoning", {})

        md_lines = [
            f"# {sev_icon} SentinelAI Security Incident Brief: `{incident_id}`",
            "",
            f"**Generated**: `{timestamp}` | **Status**: `CONTAINED` | **Engine**: Multi-Tier AI + RAG Reasoning",
            "",
            "---",
            "",
            "## 1. Executive Incident Summary",
            "",
            f"| Metric | Assessment |",
            f"| :--- | :--- |",
            f"| **Incident ID** | `{incident_id}` |",
            f"| **Severity Rating** | **`{sev}`** |",
            f"| **Classification** | **`{family}`** (`{confidence:.2f}%` Confidence) |",
            f"| **Detection Verdict** | `{verdict}` |",
            f"| **Targeted Port** | `{flow.get('dst_port', 'N/A')}` |",
            f"| **Source IP** | `{flow.get('src_ip', 'N/A')}` |",
            f"| **Destination IP** | `{flow.get('dst_ip', 'N/A')}` |",
            "",
            "---",
            "",
            "## 2. Immediate Autonomous Containment Action",
            "",
            f"> **Enforced Action**: `{containment.get('action', 'LOG_AND_MONITOR')}`  ",
            f"> **Policy**: {containment.get('description', 'Standard traffic monitoring engaged.')}",
            "",
            "---",
            ""
        ]

        if reasoning:
            prov_label = reasoning.get("provider", "Deterministic").upper()
            model_label = reasoning.get("model", "Rules")
            narrative = reasoning.get("narrative", "")
            root_cause = reasoning.get("root_cause_analysis", "")
            checklist = reasoning.get("containment_checklist", [])

            md_lines.extend([
                f"## 3. Autonomous AI Reasoning & Attack Analysis (`{prov_label}` / `{model_label}`)",
                "",
                "### 3.1 Attack Narrative",
                narrative,
                "",
                "### 3.2 Root Cause Analysis (Network Physics & ML Attribution)",
                root_cause,
                "",
                "### 3.3 SOC Responder Checklist",
                ""
            ])
            for idx, item in enumerate(checklist, 1):
                md_lines.append(f"{idx}. {item}")
            md_lines.extend(["", "---", ""])

        md_lines.extend([
            "## 4. Explainability & Network Decision Drivers (TreeSHAP)",
            "",
            "The multi-tier gatekeeper flagged this traffic flow based on physical network dynamics:",
            ""
        ])

        if flow.get("decisive_features"):
            for feat in flow["decisive_features"]:
                md_lines.append(f"* **`{feat}`**")
        else:
            md_lines.append("* Flow characteristics matched trained attack profiles.")

        md_lines.extend([
            "",
            "---",
            "",
            "## 4. Threat Attribution & Adversary Correlation",
            "",
            "Retrieved via SentinelAI's threat intelligence RAG knowledge base:",
            ""
        ])

        if attributions:
            for att in attributions:
                md_lines.append(
                    f"* **`{att.get('identifier', 'N/A')}`: {att.get('title', 'Unknown')}**  \n"
                    f"  *Source*: `{att.get('source', '').upper()}` | *Semantic Relevance*: `{att.get('relevance_score', 0.0):.4f}`"
                )
        else:
            md_lines.append("* No direct TTP correlations retrieved.")

        md_lines.extend([
            "",
            "---",
            "",
            "## 5. Authoritative Defensive Playbooks & Mitigations",
            ""
        ])

        if playbooks:
            for idx, pb in enumerate(playbooks, 1):
                md_lines.extend([
                    f"### 5.{idx} [{pb.get('source', '').upper()}] {pb.get('title', 'Playbook')}",
                    f"**Identifier**: `{pb.get('identifier', 'N/A')}`",
                    "",
                    f"{pb.get('guidance', '')}",
                    ""
                ])
        else:
            md_lines.append("* Refer to standard organizational security operating procedures.")

        md_lines.extend([
            "---",
            "",
            "*Report automatically generated by SentinelAI Autonomous Defense Engine.*"
        ])

        return "\n".join(md_lines)

    def save_report(self, incident: Dict[str, Any]) -> Path:
        """
        Saves both Markdown and JSON reports to disk.
        """
        incident_id = incident.get("incident_id", "incident")
        md_path = self.output_dir / f"{incident_id}.md"
        json_path = self.output_dir / f"{incident_id}.json"

        md_content = self.generate_markdown(incident)

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(incident, f, indent=2)

        print(f"[✓] Saved incident report to: {md_path}")
        return md_path

