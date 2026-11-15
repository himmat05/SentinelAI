"""
SentinelAI - Multi-Provider LLM Reasoning Engine
=================================================
Provides swappable reasoning backends for automated SOC incident investigation:
  1. 'deterministic' (Default): Instant (0ms), ground-truth TreeSHAP + RAG synthesis.
  2. 'ollama': Local offline LLMs (llama3.2, mistral, phi3) via Ollama REST API.
  3. 'gemini': Cloud LLMs (gemini-1.5-flash, gemini-2.0-flash) via Google Gemini API.
  4. 'openai': Cloud LLMs (gpt-4o-mini, groq, etc.) via OpenAI-compatible API.

All providers return a standardized reasoning bundle with graceful offline fallbacks.
"""

from typing import Dict, Any, Optional, List
import os
import json
import time
import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class LLMReasoningEngine:
    """
    Unified multi-provider reasoning engine for SentinelAI threat attribution.
    """
    SUPPORTED_PROVIDERS = ["deterministic", "ollama", "gemini", "openai"]

    def __init__(
        self,
        default_provider: str = "deterministic",
        ollama_base_url: Optional[str] = None,
        ollama_default_model: str = "llama3.2",
        gemini_default_model: str = "gemini-flash-lite-latest"
    ):
        self.default_provider = default_provider
        self.ollama_base_url = ollama_base_url or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.ollama_default_model = os.environ.get("SENTINEL_OLLAMA_MODEL", ollama_default_model)
        self.gemini_default_model = os.environ.get("SENTINEL_GEMINI_MODEL", gemini_default_model)

    def generate_reasoning(
        self,
        incident_context: Dict[str, Any],
        provider: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: float = 15.0
    ) -> Dict[str, Any]:
        """
        Synthesizes attack narrative, root cause analysis, and containment checklist.
        """
        chosen_provider = (provider or self.default_provider).lower().strip()
        if chosen_provider not in self.SUPPORTED_PROVIDERS:
            chosen_provider = "deterministic"

        t0 = time.time()

        if chosen_provider == "ollama":
            result = self._reason_with_ollama(incident_context, model=model, timeout=timeout_seconds)
        elif chosen_provider == "gemini":
            result = self._reason_with_gemini(incident_context, model=model, api_key=api_key, timeout=timeout_seconds)
        elif chosen_provider == "openai":
            result = self._reason_with_openai(incident_context, model=model, api_key=api_key, timeout=timeout_seconds)
        else:
            result = self._reason_deterministic(incident_context)

        latency_ms = round((time.time() - t0) * 1000.0, 2)
        result["latency_ms"] = latency_ms
        return result

    # --------------------------------------------------------------------------
    # 1. DETERMINISTIC REASONING (Ground-Truth Rule & Template Engine)
    # --------------------------------------------------------------------------
    def _reason_deterministic(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        family = ctx.get("threat_family", "Unknown")
        severity = ctx.get("severity", "MEDIUM")
        confidence = ctx.get("confidence", 0.0) * 100.0
        flow = ctx.get("flow_context", {})
        port = flow.get("dst_port", "N/A")
        features = flow.get("decisive_features", [])
        containment = ctx.get("immediate_containment", {})
        attributions = ctx.get("mitre_attribution", [])
        playbooks = ctx.get("recommended_playbooks", [])

        # 1. Attack Narrative
        narrative_map = {
            "Infiltration": (
                f"Adversary activity detected targeting service port {port}. The traffic pattern exhibits "
                f"unauthorized lateral movement mechanics characteristic of post-exploitation internal reconnaissance. "
                f"The flow demonstrates payload transmission and privilege propagation attempts across internal VLAN segments."
            ),
            "DDoS": (
                f"High-volume distributed traffic spike targeting port {port}. Ingress packet velocity exceeds normal "
                f"baseline tolerance, engineered to saturate socket buffers and exhaust upstream network bandwidth."
            ),
            "DoS": (
                f"Resource exhaustion attack targeted at port {port}. The offending host is abusing application or transport "
                f"layer handshakes to starve memory allocations and drop legitimate inbound service requests."
            ),
            "Web Exploitation": (
                f"Malicious application-layer query delivered to web service port {port}. The payload structure reflects "
                f"unverified input manipulation (e.g., SQL injection, command execution, or path traversal) designed to bypass authentication."
            ),
            "Botnet": (
                f"Command and Control (C2) beaconing behavior identified on port {port}. Periodic, structured keep-alive "
                f"packets suggest automated malware agent communication with an external adversary cluster."
            ),
            "Brute Force": (
                f"High-frequency credential stuffing / dictionary assault on authentication service port {port}. Rapid sequential "
                f"session establishments indicate automated password harvesting attempts."
            ),
            "PortScan": (
                f"Active network reconnaissance sweep across port {port}. The remote host is probing socket responsiveness "
                f"to enumerate active listening services and map internal topology prior to exploitation."
            ),
            "Fuzzing": (
                f"Malformed transport packets delivered to port {port}. Non-RFC compliant byte streams detected, indicating "
                f"protocol fuzzing designed to trigger buffer overflows or unhandled daemon exceptions."
            )
        }
        narrative = narrative_map.get(
            family,
            f"Anomalous network flow classified as {family} on port {port} with {confidence:.1f}% confidence."
        )

        # 2. Root Cause Analysis (SHAP Physical Drivers)
        if features:
            feat_bullets = "\n".join([f"  • {f}" for f in features[:4]])
            root_cause = (
                f"The multi-tier machine learning engine identified this flow as {family} based on physical network "
                f"deviations captured by TreeSHAP explainability:\n{feat_bullets}\n"
                f"These metric anomalies indicate abnormal payload ratios, burst timing, or transport flag asymmetries."
            )
        else:
            root_cause = (
                f"The multi-tier gatekeeper flagged this session due to cross-tier convergence between behavioral "
                f"deviance (Tier 1) and supervised decision boundaries (Tier 2 & 3)."
            )

        # 3. SOC Containment Checklist
        checklist = [
            f"Enforce automated policy: `{containment.get('action', 'LOG_AND_MONITOR')}` - {containment.get('description', '')}",
            f"Isolate or rate-limit communicating endpoint `{flow.get('src_ip', 'Source IP')}` at network edge.",
            f"Inspect target endpoint `{flow.get('dst_ip', 'Destination IP')}` for signs of persistence or active sessions."
        ]
        if playbooks:
            first_pb = playbooks[0]
            checklist.append(f"Review authoritative playbook: {first_pb.get('title', 'Remediation Guide')} ({first_pb.get('source', '').upper()})")

        return {
            "provider": "deterministic",
            "model": "Sentinel-Rules-v1 (Zero Latency)",
            "narrative": narrative,
            "root_cause_analysis": root_cause,
            "containment_checklist": checklist,
            "is_fallback": False
        }

    # --------------------------------------------------------------------------
    # 2. OLLAMA LOCAL REASONING (Offline Local LLM)
    # --------------------------------------------------------------------------
    def _reason_with_ollama(
        self,
        ctx: Dict[str, Any],
        model: Optional[str] = None,
        timeout: float = 15.0
    ) -> Dict[str, Any]:
        target_model = model or self.ollama_default_model
        prompt = self._build_prompt(ctx)

        try:
            url = f"{self.ollama_base_url.rstrip('/')}/api/generate"
            payload = {
                "model": target_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "top_p": 0.9,
                    "num_predict": 512
                }
            }
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, json=payload)

            if resp.status_code == 200:
                data = resp.json()
                llm_text = data.get("response", "").strip()
                parsed = self._parse_llm_response(llm_text)
                parsed["provider"] = "ollama"
                parsed["model"] = target_model
                parsed["is_fallback"] = False
                return parsed
            else:
                fallback = self._reason_deterministic(ctx)
                fallback["provider"] = "ollama (fallback -> deterministic)"
                fallback["model"] = f"{target_model} [HTTP {resp.status_code}]"
                fallback["is_fallback"] = True
                fallback["fallback_reason"] = f"Ollama returned HTTP status {resp.status_code}: {resp.text[:200]}"
                return fallback

        except Exception as e:
            fallback = self._reason_deterministic(ctx)
            fallback["provider"] = "ollama (fallback -> deterministic)"
            fallback["model"] = f"{target_model} [Unreachable]"
            fallback["is_fallback"] = True
            fallback["fallback_reason"] = (
                f"Ollama daemon unreachable at {self.ollama_base_url} ({str(e)}). "
                "Ensure Ollama is running (`ollama run " + target_model + "`) or switch to 'deterministic'."
            )
            return fallback

    # --------------------------------------------------------------------------
    # 3. GOOGLE GEMINI REASONING (Cloud API)
    # --------------------------------------------------------------------------
    def _reason_with_gemini(
        self,
        ctx: Dict[str, Any],
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 20.0
    ) -> Dict[str, Any]:
        target_model = model or self.gemini_default_model
        key = api_key or os.environ.get("GEMINI_API_KEY", "")

        if not key:
            fallback = self._reason_deterministic(ctx)
            fallback["provider"] = "gemini (fallback -> deterministic)"
            fallback["model"] = f"{target_model} [Missing API Key]"
            fallback["is_fallback"] = True
            fallback["fallback_reason"] = "GEMINI_API_KEY is not set. Provide an API key in the UI or environment."
            return fallback

        prompt = self._build_prompt(ctx)

        # Smart fallback list for active Gemini model names
        legacy_map = {
            "gemini-1.5-flash": "gemini-flash-lite-latest",
            "gemini-1.5-pro": "gemini-pro-latest",
            "gemini-2.0-flash": "gemini-flash-lite-latest",
            "gemini-2.5-flash": "gemini-flash-lite-latest"
        }
        primary = legacy_map.get(target_model, target_model)
        models_to_try = [primary]
        if "gemini-flash-lite-latest" not in models_to_try:
            models_to_try.append("gemini-flash-lite-latest")
        if "gemini-3.8-flash" not in models_to_try:
            models_to_try.append("gemini-3.8-flash")

        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 600
            }
        }

        last_error = ""
        for candidate_model in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{candidate_model}:generateContent?key={key}"
            try:
                with httpx.Client(timeout=timeout) as client:
                    resp = client.post(url, json=payload)

                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        llm_text = "".join([p.get("text", "") for p in parts]).strip()
                        parsed = self._parse_llm_response(llm_text)
                        parsed["provider"] = "gemini"
                        parsed["model"] = candidate_model
                        parsed["is_fallback"] = False
                        return parsed
                else:
                    last_error = f"HTTP {resp.status_code} ({candidate_model}): {resp.text[:150]}"
            except Exception as e:
                last_error = f"{candidate_model} exception: {str(e)}"

        fallback = self._reason_deterministic(ctx)
        fallback["provider"] = "gemini (fallback -> deterministic)"
        fallback["model"] = f"{target_model} [API Error]"
        fallback["is_fallback"] = True
        fallback["fallback_reason"] = f"Gemini API request failed across tested models: {last_error}"
        return fallback

    # --------------------------------------------------------------------------
    # 4. OPENAI-COMPATIBLE REASONING
    # --------------------------------------------------------------------------
    def _reason_with_openai(
        self,
        ctx: Dict[str, Any],
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 15.0
    ) -> Dict[str, Any]:
        target_model = model or "gpt-4o-mini"
        key = api_key or os.environ.get("OPENAI_API_KEY", "")

        if not key:
            fallback = self._reason_deterministic(ctx)
            fallback["provider"] = "openai (fallback -> deterministic)"
            fallback["model"] = f"{target_model} [Missing Key]"
            fallback["is_fallback"] = True
            fallback["fallback_reason"] = "OPENAI_API_KEY is not set."
            return fallback

        prompt = self._build_prompt(ctx)
        url = "https://api.openai.com/v1/chat/completions"

        try:
            headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
            payload = {
                "model": target_model,
                "messages": [
                    {"role": "system", "content": "You are SentinelAI's Senior Tier-3 SOC Incident Commander."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2,
                "max_tokens": 512
            }
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, headers=headers, json=payload)

            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"].strip()
                parsed = self._parse_llm_response(content)
                parsed["provider"] = "openai"
                parsed["model"] = target_model
                parsed["is_fallback"] = False
                return parsed

            fallback = self._reason_deterministic(ctx)
            fallback["provider"] = "openai (fallback -> deterministic)"
            fallback["is_fallback"] = True
            fallback["fallback_reason"] = f"OpenAI API returned HTTP {resp.status_code}: {resp.text[:200]}"
            return fallback

        except Exception as e:
            fallback = self._reason_deterministic(ctx)
            fallback["provider"] = "openai (fallback -> deterministic)"
            fallback["is_fallback"] = True
            fallback["fallback_reason"] = f"OpenAI API call failed: {str(e)}"
            return fallback

    # --------------------------------------------------------------------------
    # PROMPT BUILDER & PARSER
    # --------------------------------------------------------------------------
    def _build_prompt(self, ctx: Dict[str, Any]) -> str:
        family = ctx.get("threat_family", "Unknown")
        severity = ctx.get("severity", "MEDIUM")
        confidence = ctx.get("confidence", 0.0) * 100.0
        flow = ctx.get("flow_context", {})
        port = flow.get("dst_port", "N/A")
        src_ip = flow.get("src_ip", "N/A")
        dst_ip = flow.get("dst_ip", "N/A")
        features = flow.get("decisive_features", [])
        containment = ctx.get("immediate_containment", {})
        attributions = ctx.get("mitre_attribution", [])
        playbooks = ctx.get("recommended_playbooks", [])

        feat_str = "\n".join([f"- {f}" for f in features]) if features else "- Supervised LightGBM multi-feature threshold"
        ttp_str = "\n".join([f"- [{a.get('source', '').upper()}] {a.get('identifier')}: {a.get('title')}" for a in attributions]) if attributions else "None retrieved"
        pb_str = "\n".join([f"- [{p.get('source', '').upper()}] {p.get('title')}: {p.get('guidance', '')[:180]}" for p in playbooks]) if playbooks else "None retrieved"

        return f"""You are SentinelAI's Senior Tier-3 SOC Incident Commander.
Analyze this real-time network intrusion alert flagged by SentinelAI's multi-tier machine learning defense engine.

INCIDENT METADATA:
- Threat Category: {family}
- Severity: {severity} (Detection Certainty: {confidence:.2f}%)
- Target Socket: {dst_ip}:{port}
- Source IP: {src_ip}
- Autonomous Firewall Action: {containment.get('action')} - {containment.get('description')}

PHYSICAL FLOW DECISION DRIVERS (TreeSHAP Feature Attribution):
{feat_str}

RETRIEVED MITRE ATT&CK / CISA THREAT CONTEXT:
{ttp_str}

RETRIEVED PLAYBOOKS & DEFENSES:
{pb_str}

TASK:
Produce a concise, professional SOC investigation brief formatted strictly into three sections:
### 1. ATTACK NARRATIVE
(2-3 sentences explaining the adversary's technical intent, targeted service, and operational risk)

### 2. ROOT CAUSE ANALYSIS (NETWORK PHYSICS)
(2-3 sentences explaining why the machine learning engine flagged this based on the TreeSHAP feature drivers above)

### 3. CONTAINMENT & REMEDIATION CHECKLIST
(3-4 numbered actionable mitigation steps for SOC responders)
"""

    def _parse_llm_response(self, text: str) -> Dict[str, Any]:
        """Parses LLM markdown response into structured sections."""
        narrative = ""
        root_cause = ""
        checklist = []

        sections = text.split("### ")
        for sec in sections:
            sec_clean = sec.strip()
            if not sec_clean:
                continue

            lines = sec_clean.split("\n", 1)
            header = lines[0].strip().upper()
            body = lines[1].strip() if len(lines) > 1 else ""

            if "ATTACK NARRATIVE" in header or "1." in header:
                narrative = body
            elif "ROOT CAUSE" in header or "2." in header:
                root_cause = body
            elif "CONTAINMENT" in header or "CHECKLIST" in header or "3." in header:
                for line in body.split("\n"):
                    line_clean = line.strip()
                    if line_clean and (line_clean[0].isdigit() or line_clean.startswith("-") or line_clean.startswith("*")):
                        checklist.append(line_clean.lstrip("0123456789.-* "))

        # Fallback if structure wasn't strict
        if not narrative and text:
            narrative = text[:300].strip()
        if not checklist:
            checklist = [
                "Execute automated line-rate containment rule.",
                "Isolate originating IP address at edge firewall.",
                "Conduct host forensic review for indicators of compromise (IOCs)."
            ]

        return {
            "narrative": narrative,
            "root_cause_analysis": root_cause,
            "containment_checklist": checklist
        }


# Global singleton instance
_llm_reasoning_engine: Optional[LLMReasoningEngine] = None

def get_llm_reasoning_engine() -> LLMReasoningEngine:
    global _llm_reasoning_engine
    if _llm_reasoning_engine is None:
        _llm_reasoning_engine = LLMReasoningEngine()
    return _llm_reasoning_engine
