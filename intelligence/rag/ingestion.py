"""
SentinelAI - Stage 09: Threat Intelligence Ingestion & Chunking Pipeline
========================================================================
This module normalizes, parses, and chunks heterogeneous threat intelligence
sources (MITRE ATT&CK STIX 2.1, CISA KEV, NVD CVEs, and OWASP Top 10 2025)
into a unified schema optimized for vector embeddings and ChromaDB RAG retrieval.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from pathlib import Path
import json
import re
import hashlib
import os


# ==============================================================================
# 1. UNIFIED CHUNK DATA SCHEMA
# ==============================================================================

@dataclass
class ThreatIntelChunk:
    """
    Standardized, dense representation of a threat intelligence unit
    ready for dense vector embedding and semantic search.
    """
    chunk_id: str               # Deterministic unique hash (e.g., "mitre:T1059:001", "cisa:CVE-2024-21413")
    text: str                   # Rich semantic text block optimized for embedding
    source: str                 # "mitre_attack" | "cisa_kev" | "nvd" | "owasp_top10"
    category: str               # Mapped to SentinelAI 9 ML attack families
    identifier: str             # Canonical identifier (T1059, CVE-2024-21413, A06:2025)
    title: str                  # Human-readable title
    severity: str               # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ==============================================================================
# 2. CATEGORY MAPPING HEURISTICS
# ==============================================================================

SENTINEL_CLASSES = [
    "Benign",
    "DDoS",
    "DoS",
    "PortScan",
    "Brute Force",
    "Web Exploitation",
    "Botnet",
    "Infiltration",
    "Fuzzing",
    "General"
]

def map_text_to_sentinel_category(text: str, default: str = "Infiltration") -> str:
    """
    Heuristically maps threat intelligence text and keywords to SentinelAI's 9 ML attack families.
    """
    lower = text.lower()
    
    # Priority 1: Volumetric & DoS / DDoS
    if any(k in lower for k in ["distributed denial of service", "ddos", "syn flood", "udp flood", "amplification attack"]):
        return "DDoS"
    if any(k in lower for k in ["denial of service", "denial-of-service", "dos attack", "resource exhaustion"]):
        return "DoS"
    
    # Priority 2: Scanning & Reconnaissance
    if any(k in lower for k in ["port scan", "network scan", "reconnaissance", "ip sweep", "vulnerability scanner", "active scanning"]):
        return "PortScan"
    
    # Priority 3: Authentication & Password Cracking
    if any(k in lower for k in ["brute force", "password spraying", "credential stuffing", "dictionary attack", "default credentials", "cracking"]):
        return "Brute Force"
    
    # Priority 4: Web Application Exploits
    if any(k in lower for k in ["sql injection", "sqli", "cross-site scripting", "xss", "ssrf", "path traversal", 
                               "command injection", "directory traversal", "file inclusion", "owasp", "web application"]):
        return "Web Exploitation"
    
    # Priority 5: Command & Control / Botnet
    if any(k in lower for k in ["botnet", "command and control", "c2", "beaconing", "covert channel", "zombie network"]):
        return "Botnet"
    
    # Priority 6: Fuzzing / Memory Corruption / Malformed Inputs
    if any(k in lower for k in ["fuzzing", "buffer overflow", "heap overflow", "out-of-bounds write", "format string", "memory corruption"]):
        return "Fuzzing"
    
    # Priority 7: Lateral movement, malware, Trojans, backdoor, stealth persistence
    if any(k in lower for k in ["lateral movement", "backdoor", "trojan", "ransomware", "privilege escalation", "persistence", "rootkit", "exploit"]):
        return "Infiltration"
        
    return default


# ==============================================================================
# 3. MITRE ATT&CK STIX 2.1 PARSER
# ==============================================================================

class MitreAttackParser:
    """
    Parses MITRE ATT&CK Enterprise Matrix STIX 2.1 graph data.
    Extracts active techniques, mitigations, malware, and threat actor profiles.
    """
    def __init__(self, stix_path: Path):
        self.stix_path = Path(stix_path)

    def parse(self) -> List[ThreatIntelChunk]:
        if not self.stix_path.exists():
            raise FileNotFoundError(f"MITRE STIX file not found: {self.stix_path}")

        with open(self.stix_path, "r", encoding="utf-8") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        
        # Build mitigation lookup map (course-of-action ID -> mitigation name & desc)
        mitigations_map = {}
        for obj in objects:
            if obj.get("type") == "course-of-action" and not obj.get("revoked", False):
                mit_id = obj.get("id")
                ext_id = "N/A"
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        ext_id = ref.get("external_id", "N/A")
                        break
                mitigations_map[mit_id] = {
                    "ext_id": ext_id,
                    "name": obj.get("name", "Unknown Mitigation"),
                    "description": obj.get("description", "")
                }

        chunks: List[ThreatIntelChunk] = []

        # 1. Parse attack-pattern (Techniques and Sub-techniques)
        for obj in objects:
            if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
                continue

            # Extract technique ID
            tech_id = "N/A"
            tech_url = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id", "N/A")
                    tech_url = ref.get("url", "")
                    break

            name = obj.get("name", "Unknown Technique")
            description = obj.get("description", "").strip()
            is_sub = obj.get("x_mitre_is_subtechnique", False)
            platforms = obj.get("x_mitre_platforms", [])
            detection = obj.get("x_mitre_detection", "").strip()

            # Kill chain tactics
            tactics = [
                kc.get("phase_name")
                for kc in obj.get("kill_chain_phases", [])
                if kc.get("kill_chain_name") == "mitre-attack"
            ]

            # Categorization
            tactic_text = " ".join(tactics)
            combined_context = f"{name} {tactic_text} {description[:400]}"
            category = map_text_to_sentinel_category(combined_context, default="Infiltration")

            # Determine severity based on tactical impact
            severity = "HIGH"
            if any(t in ["impact", "exfiltration", "credential-access"] for t in tactics):
                severity = "CRITICAL"
            elif any(t in ["initial-access", "privilege-escalation", "defense-evasion"] for t in tactics):
                severity = "HIGH"
            elif any(t in ["reconnaissance", "discovery"] for t in tactics):
                severity = "MEDIUM"

            # Dense text representation for embedding
            text_blocks = [
                f"[MITRE ATT&CK TECHNIQUE] {tech_id}: {name}",
                f"Tactics: {', '.join(tactics) if tactics else 'N/A'}",
                f"Platforms: {', '.join(platforms) if platforms else 'All'}",
                f"Is Sub-Technique: {'Yes' if is_sub else 'No'}",
                f"Description: {description}",
            ]
            if detection:
                text_blocks.append(f"Detection Guidance: {detection}")

            text = "\n\n".join(text_blocks)
            chunk_id = f"mitre:tech:{tech_id.replace('.', '_')}"

            metadata = {
                "technique_id": tech_id,
                "tactics": tactics,
                "platforms": platforms,
                "is_subtechnique": is_sub,
                "url": tech_url,
                "object_type": "attack-pattern"
            }

            chunks.append(ThreatIntelChunk(
                chunk_id=chunk_id,
                text=text,
                source="mitre_attack",
                category=category,
                identifier=tech_id,
                title=name,
                severity=severity,
                metadata=metadata
            ))

        # 2. Parse course-of-action (Defensive Mitigations)
        for mit_id, mit_data in mitigations_map.items():
            ext_id = mit_data["ext_id"]
            name = mit_data["name"]
            desc = mit_data["description"].strip()
            if not desc:
                continue

            text = f"[MITRE ATT&CK MITIGATION] {ext_id}: {name}\n\nDescription: {desc}"
            chunk_id = f"mitre:mit:{ext_id.replace('.', '_')}"

            chunks.append(ThreatIntelChunk(
                chunk_id=chunk_id,
                text=text,
                source="mitre_attack",
                category="General",
                identifier=ext_id,
                title=f"Mitigation: {name}",
                severity="INFO",
                metadata={
                    "mitigation_id": ext_id,
                    "object_type": "course-of-action"
                }
            ))

        # 3. Parse malware and intrusion-set (Threat Actors & Software)
        for obj in objects:
            obj_type = obj.get("type")
            if obj_type not in ["malware", "intrusion-set"] or obj.get("revoked", False):
                continue

            name = obj.get("name", "Unknown Entity")
            description = obj.get("description", "").strip()
            if not description:
                continue

            aliases = obj.get("aliases", [])
            ext_id = "N/A"
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "N/A")
                    break

            label_prefix = "MALWARE FAMILY" if obj_type == "malware" else "THREAT ACTOR GROUP"
            text_blocks = [
                f"[MITRE ATT&CK {label_prefix}] {ext_id}: {name}",
                f"Aliases: {', '.join(aliases) if aliases else 'None'}",
                f"Description: {description}"
            ]

            category = map_text_to_sentinel_category(f"{name} {description}", default="Infiltration")
            chunk_id = f"mitre:{obj_type[:3]}:{ext_id.replace('.', '_') if ext_id != 'N/A' else hashlib.md5(name.encode()).hexdigest()[:8]}"

            chunks.append(ThreatIntelChunk(
                chunk_id=chunk_id,
                text="\n\n".join(text_blocks),
                source="mitre_attack",
                category=category,
                identifier=ext_id,
                title=f"{name} ({label_prefix.title()})",
                severity="HIGH" if obj_type == "malware" else "CRITICAL",
                metadata={
                    "entity_id": ext_id,
                    "aliases": aliases,
                    "object_type": obj_type
                }
            ))

        return chunks


# ==============================================================================
# 4. CISA KEV (KNOWN EXPLOITED VULNERABILITIES) PARSER
# ==============================================================================

class CisaKevParser:
    """
    Parses CISA Known Exploited Vulnerabilities catalog.
    Every record represents an active in-the-wild weaponized exploit.
    """
    def __init__(self, kev_path: Path):
        self.kev_path = Path(kev_path)

    def parse(self) -> List[ThreatIntelChunk]:
        if not self.kev_path.exists():
            raise FileNotFoundError(f"CISA KEV file not found: {self.kev_path}")

        with open(self.kev_path, "r", encoding="utf-8") as f:
            catalog = json.load(f)

        vulns = catalog.get("vulnerabilities", [])
        chunks: List[ThreatIntelChunk] = []

        for item in vulns:
            cve_id = item.get("cveID", "UNKNOWN-CVE")
            vendor = item.get("vendorProject", "Unknown Vendor")
            product = item.get("product", "Unknown Product")
            vuln_name = item.get("vulnerabilityName", "")
            short_desc = item.get("shortDescription", "").strip()
            req_action = item.get("requiredAction", "").strip()
            date_added = item.get("dateAdded", "")
            due_date = item.get("dueDate", "")
            ransomware = item.get("knownRansomwareCampaignUse", "Unknown")

            is_ransomware = (ransomware.lower() == "known")
            severity = "CRITICAL" if is_ransomware else "HIGH"

            combined_text = f"{vuln_name} {short_desc} {vendor} {product}"
            category = map_text_to_sentinel_category(combined_text, default="Infiltration")

            text_blocks = [
                f"[CISA KNOWN EXPLOITED VULNERABILITY] {cve_id}: {vuln_name}",
                f"Vendor & Product: {vendor} / {product}",
                f"Date Added to KEV: {date_added} | Remediation Due Date: {due_date}",
                f"Known Ransomware Campaign Weaponization: {'YES (CONFIRMED)' if is_ransomware else 'Not Documented'}",
                f"Vulnerability Description: {short_desc}",
                f"Mandatory Mitigation / Action: {req_action}"
            ]

            text = "\n\n".join(text_blocks)
            chunk_id = f"cisa:{cve_id}"

            metadata = {
                "cve_id": cve_id,
                "vendor": vendor,
                "product": product,
                "date_added": date_added,
                "due_date": due_date,
                "ransomware_use": is_ransomware,
                "required_action": req_action
            }

            chunks.append(ThreatIntelChunk(
                chunk_id=chunk_id,
                text=text,
                source="cisa_kev",
                category=category,
                identifier=cve_id,
                title=f"{cve_id}: {vuln_name}",
                severity=severity,
                metadata=metadata
            ))

        return chunks


# ==============================================================================
# 5. NVD (NATIONAL VULNERABILITY DATABASE) PARSER
# ==============================================================================

class NvdParser:
    """
    Parses structured NVD CVE entries with CVSS v2/v3 scoring and CWE mappings.
    """
    def __init__(self, nvd_path: Path):
        self.nvd_path = Path(nvd_path)

    def parse(self) -> List[ThreatIntelChunk]:
        if not self.nvd_path.exists():
            return []

        with open(self.nvd_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulnerabilities = data.get("vulnerabilities", [])
        chunks: List[ThreatIntelChunk] = []

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            published = cve.get("published", "")[:10]

            # English description
            desc_list = cve.get("descriptions", [])
            eng_desc = next((d.get("value") for d in desc_list if d.get("lang") == "en"), "").strip()

            # Weaknesses (CWE)
            cwes = []
            for w in cve.get("weaknesses", []):
                for desc in w.get("description", []):
                    if desc.get("lang") == "en":
                        cwes.append(desc.get("value"))

            # Metrics (CVSS v3.1 / v2.0)
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "MEDIUM"

            if "cvssMetricV31" in metrics:
                data_m = metrics["cvssMetricV31"][0].get("cvssData", {})
                cvss_score = data_m.get("baseScore")
                severity = data_m.get("baseSeverity", "MEDIUM").upper()
            elif "cvssMetricV2" in metrics:
                data_m = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_score = data_m.get("baseScore")
                raw_sev = metrics["cvssMetricV2"][0].get("baseSeverity", "MEDIUM")
                severity = raw_sev.upper() if raw_sev else "MEDIUM"

            category = map_text_to_sentinel_category(f"{eng_desc} {' '.join(cwes)}", default="Web Exploitation")

            text_blocks = [
                f"[NVD VULNERABILITY METRIC] {cve_id}",
                f"Published Date: {published}",
                f"CVSS Base Score: {cvss_score if cvss_score is not None else 'N/A'} ({severity})",
                f"Common Weakness Enumeration (CWE): {', '.join(cwes) if cwes else 'N/A'}",
                f"Vulnerability Description: {eng_desc}"
            ]

            text = "\n\n".join(text_blocks)
            chunk_id = f"nvd:{cve_id}"

            metadata = {
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "cwes": cwes,
                "published": published
            }

            chunks.append(ThreatIntelChunk(
                chunk_id=chunk_id,
                text=text,
                source="nvd",
                category=category,
                identifier=cve_id,
                title=f"{cve_id} (NVD Vulnerability)",
                severity=severity,
                metadata=metadata
            ))

        return chunks


# ==============================================================================
# 6. OWASP TOP 10 (2025) MARKDOWN HEADING PARSER
# ==============================================================================

class OwaspMarkdownParser:
    """
    Parses OWASP Top 10 (2025 Release) Markdown documentation files.
    Splits long-form playbooks into semantic, heading-aligned chunks (300-500 tokens).
    """
    def __init__(self, owasp_dir: Path):
        self.owasp_dir = Path(owasp_dir)

    def _clean_markdown(self, text: str) -> str:
        # Strip markdown image syntax ![alt](url){attributes}
        text = re.sub(r"!\[.*?\](?:\(.*?\))?(?:\{.*?\})?", "", text)
        # Strip excessive blank lines
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    def parse(self) -> List[ThreatIntelChunk]:
        if not self.owasp_dir.exists():
            raise FileNotFoundError(f"OWASP directory not found: {self.owasp_dir}")

        md_files = list(self.owasp_dir.glob("*.md"))
        chunks: List[ThreatIntelChunk] = []

        for fpath in md_files:
            fname = fpath.name
            # Skip landing page / table of contents index.md
            if fname.lower() in ["index.md", "readme.md"]:
                continue

            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()

            content = self._clean_markdown(content)

            # Extract main doc title from first header (# Title)
            h1_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
            doc_title = h1_match.group(1).strip() if h1_match else fname.replace(".md", "").replace("_", " ")

            # Extract category code e.g. "A05:2025" from filename or title
            cat_match = re.search(r"(A\d{2})_2025", fname)
            category_code = cat_match.group(1) + ":2025" if cat_match else "OWASP:2025"

            # Map category code to SentinelAI attack class
            code_category_map = {
                "A01:2025": "Web Exploitation",
                "A02:2025": "Web Exploitation",
                "A03:2025": "Infiltration",
                "A04:2025": "Web Exploitation",
                "A05:2025": "Web Exploitation",
                "A06:2025": "Web Exploitation",
                "A07:2025": "Brute Force",
                "A08:2025": "Infiltration",
                "A09:2025": "General",
                "A10:2025": "Fuzzing"
            }
            category = code_category_map.get(category_code, "Web Exploitation")

            # Split document by H2 headers (## Header)
            sections = re.split(r"\n(?=##\s+)", content)

            for idx, sec in enumerate(sections):
                sec = sec.strip()
                if not sec:
                    continue

                # Extract section title
                sec_header_match = re.match(r"^##\s+(.+)$", sec, re.MULTILINE)
                if sec_header_match:
                    sec_title = sec_header_match.group(1).strip()
                    sec_body = re.sub(r"^##\s+.+$", "", sec, flags=re.MULTILINE).strip()
                else:
                    sec_title = "Overview & Summary" if idx == 0 else f"Section {idx+1}"
                    # Remove the top-level H1 header from the overview body
                    sec_body = re.sub(r"^#\s+.+$", "", sec, flags=re.MULTILINE).strip()

                if len(sec_body) < 40:  # Skip trivial headings or empty blocks
                    continue

                # Determine section purpose (Prevention, Scenario, Description)
                lower_title = sec_title.lower()
                severity = "HIGH"
                if "prevent" in lower_title or "remediation" in lower_title:
                    sec_type = "Mitigation Playbook"
                    severity = "INFO"
                elif "scenario" in lower_title or "attack" in lower_title:
                    sec_type = "Attack Scenario"
                    severity = "HIGH"
                elif "how to" in lower_title or "cwe" in lower_title:
                    sec_type = "Reference & Prevention"
                    severity = "INFO"
                else:
                    sec_type = "Threat Description"

                text = f"[OWASP TOP 10 2025] {category_code} - {doc_title}\nSection: {sec_title} ({sec_type})\n\n{sec_body}"
                
                # Deterministic unique chunk ID using filename + section index + slug
                clean_fname = re.sub(r"[^a-zA-Z0-9_]", "_", fname.replace(".md", "").lower())
                clean_sec_slug = re.sub(r"[^a-zA-Z0-9_]", "_", sec_title.lower())[:30]
                chunk_id = f"owasp:{clean_fname}:sec_{idx}_{clean_sec_slug}"

                metadata = {
                    "document": fname,
                    "document_title": doc_title,
                    "category_code": category_code,
                    "section_title": sec_title,
                    "section_type": sec_type
                }

                chunks.append(ThreatIntelChunk(
                    chunk_id=chunk_id,
                    text=text,
                    source="owasp_top10",
                    category=category,
                    identifier=category_code,
                    title=f"{category_code}: {sec_title}",
                    severity=severity,
                    metadata=metadata
                ))

        return chunks


# ==============================================================================
# 7. UNIFIED THREAT INTELLIGENCE INGESTION PIPELINE
# ==============================================================================

class ThreatIntelPipeline:
    """
    Master orchestrator to parse, harmonize, and export all 4 raw threat feeds
    into structured vector chunks.
    """
    def __init__(self, project_root: Optional[Path] = None):
        if project_root is None:
            # Default to SentinelAI root relative to this script
            self.root = Path(__file__).resolve().parent.parent.parent
        else:
            self.root = Path(project_root)

        self.raw_dir = self.root / "intelligence" / "data" / "raw"
        self.processed_dir = self.root / "intelligence" / "data" / "processed"
        self.processed_dir.mkdir(parents=True, exist_ok=True)

        self.mitre_path = self.raw_dir / "mitre_attack" / "enterprise-attack.json"
        self.kev_path = self.raw_dir / "cisa" / "known_exploited_vulnerabilities.json"
        self.nvd_path = self.raw_dir / "nvd" / "sql_injection_sample.json"
        self.owasp_dir = self.raw_dir / "owasp" / "repository" / "2025" / "docs" / "en"

    def run_ingestion(self) -> List[ThreatIntelChunk]:
        """
        Executes all parsers and aggregates chunks into a unified list.
        """
        all_chunks: List[ThreatIntelChunk] = []

        # 1. MITRE ATT&CK
        print(f"[*] Ingesting MITRE ATT&CK Enterprise Matrix from {self.mitre_path.name}...")
        if self.mitre_path.exists():
            mitre_parser = MitreAttackParser(self.mitre_path)
            mitre_chunks = mitre_parser.parse()
            print(f"    ✓ Extracted {len(mitre_chunks):,} MITRE chunks (techniques, mitigations, malware, actors).")
            all_chunks.extend(mitre_chunks)
        else:
            print(f"    [!] Warning: {self.mitre_path} not found.")

        # 2. CISA KEV
        print(f"[*] Ingesting CISA Known Exploited Vulnerabilities from {self.kev_path.name}...")
        if self.kev_path.exists():
            cisa_parser = CisaKevParser(self.kev_path)
            cisa_chunks = cisa_parser.parse()
            print(f"    ✓ Extracted {len(cisa_chunks):,} CISA KEV weaponized vulnerability chunks.")
            all_chunks.extend(cisa_chunks)
        else:
            print(f"    [!] Warning: {self.kev_path} not found.")

        # 3. NVD Sample
        print(f"[*] Ingesting NVD Structured Vulnerability Metrics from {self.nvd_path.name}...")
        if self.nvd_path.exists():
            nvd_parser = NvdParser(self.nvd_path)
            nvd_chunks = nvd_parser.parse()
            print(f"    ✓ Extracted {len(nvd_chunks):,} NVD metric chunks.")
            all_chunks.extend(nvd_chunks)
        else:
            print(f"    [!] Notice: {self.nvd_path} not found (skipping sample).")

        # 4. OWASP Top 10 (2025)
        print(f"[*] Ingesting OWASP Top 10 (2025) Markdown Playbooks from {self.owasp_dir.name}...")
        if self.owasp_dir.exists():
            owasp_parser = OwaspMarkdownParser(self.owasp_dir)
            owasp_chunks = owasp_parser.parse()
            print(f"    ✓ Extracted {len(owasp_chunks):,} OWASP semantic heading chunks.")
            all_chunks.extend(owasp_chunks)
        else:
            print(f"    [!] Warning: {self.owasp_dir} not found.")

        print(f"\n[+] Total Unified Threat Intelligence Chunks: {len(all_chunks):,}")
        return all_chunks

    def save_chunks(self, chunks: List[ThreatIntelChunk], filename: str = "threat_intel_chunks.json") -> Path:
        """
        Saves chunks to a JSON manifest in the processed directory.
        """
        out_path = self.processed_dir / filename
        data = [c.to_dict() for c in chunks]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[✓] Saved {len(chunks):,} chunks to: {out_path}")
        return out_path

    def get_summary(self, chunks: List[ThreatIntelChunk]) -> Dict[str, Any]:
        """
        Generates statistical distribution summary across sources, categories, and severities.
        """
        sources = {}
        categories = {}
        severities = {}

        for c in chunks:
            sources[c.source] = sources.get(c.source, 0) + 1
            categories[c.category] = categories.get(c.category, 0) + 1
            severities[c.severity] = severities.get(c.severity, 0) + 1

        return {
            "total_chunks": len(chunks),
            "by_source": sources,
            "by_category": categories,
            "by_severity": severities
        }


# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

if __name__ == "__main__":
    pipeline = ThreatIntelPipeline()
    chunks = pipeline.run_ingestion()
    pipeline.save_chunks(chunks)

    summary = pipeline.get_summary(chunks)
    print("\n" + "=" * 60)
    print("  INGESTION SUMMARY & DISTRIBUTION")
    print("=" * 60)
    print(f"Total Chunks: {summary['total_chunks']:,}\n")
    print("By Knowledge Source:")
    for src, count in summary["by_source"].items():
        print(f"  • {src:<20}: {count:>6,} ({count/summary['total_chunks']*100:.1f}%)")

    print("\nBy SentinelAI ML Attack Class:")
    for cat, count in sorted(summary["by_category"].items(), key=lambda x: -x[1]):
        print(f"  • {cat:<20}: {count:>6,} ({count/summary['total_chunks']*100:.1f}%)")

    print("\nBy Severity Rating:")
    for sev, count in sorted(summary["by_severity"].items(), key=lambda x: -x[1]):
        print(f"  • {sev:<20}: {count:>6,} ({count/summary['total_chunks']*100:.1f}%)")
    print("=" * 60)

