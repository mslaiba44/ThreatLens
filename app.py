"""
app.py
======
ThreatLens - AI-Powered Threat Intelligence Analysis (Streamlit UI)
AI interpretation powered by Groq (Llama 3.3 70B).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import requests
import streamlit as st

from sources import SOURCES, detect_ioc_type, is_valid_ioc


st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

CUSTOM_CSS = """
<style>
    .stApp { background-color: #0b0f14; }
    h1, h2, h3 { color: #e6edf3; }
    .tl-tagline { color: #8b949e; font-size: 1.05rem; margin-top: -0.6rem; margin-bottom: 1.5rem; }
    .tl-card { background-color: #111820; border: 1px solid #22303c; border-radius: 10px; padding: 1.1rem 1.3rem; margin-bottom: 0.9rem; }
    .tl-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 999px; font-weight: 600; font-size: 0.85rem; letter-spacing: 0.02em; }
    .tl-badge-safe { background-color: #0d3321; color: #4ade80; border: 1px solid #1c5c37; }
    .tl-badge-suspicious { background-color: #3a2c0a; color: #facc15; border: 1px solid #6b4f10; }
    .tl-badge-malicious { background-color: #3a0d0d; color: #f87171; border: 1px solid #6b1a1a; }
    .tl-badge-unknown { background-color: #1e2530; color: #9ca3af; border: 1px solid #333d4a; }
    .tl-metric-label { color: #8b949e; font-size: 0.85rem; }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


IOC_TYPE_LABELS = {"IP Address": "ip", "Domain": "domain", "URL": "url"}
KNOWLEDGE_LEVELS = ["Beginner", "Intermediate", "Expert"]

VERDICT_BADGE_CLASS = {
    "SAFE": "tl-badge-safe", "SUSPICIOUS": "tl-badge-suspicious",
    "MALICIOUS": "tl-badge-malicious", "UNKNOWN": "tl-badge-unknown",
}
SOURCE_VERDICT_BADGE_CLASS = {
    "safe": "tl-badge-safe", "suspicious": "tl-badge-suspicious",
    "malicious": "tl-badge-malicious", "unknown": "tl-badge-unknown",
}


with st.sidebar:
    st.markdown("## 🛡️ ThreatLens")
    st.markdown("---")
    ioc_type_label = st.radio("IOC Type", list(IOC_TYPE_LABELS.keys()), index=1)
    ioc_type = IOC_TYPE_LABELS[ioc_type_label]
    st.markdown("---")
    knowledge_level = st.radio("Knowledge Level", KNOWLEDGE_LEVELS, index=1)
    st.markdown("---")
    st.caption("Sources: VirusTotal · WHOIS")
    st.caption("AI Interpretation: Groq (Llama 3.3)")


st.markdown("# 🛡️ ThreatLens")
st.markdown('<div class="tl-tagline">AI-Powered Threat Intelligence Analysis</div>', unsafe_allow_html=True)

ioc_input = st.text_input(
    "Enter IP address, domain, or URL",
    placeholder="e.g. 8.8.8.8, example.com, or https://example.com/login",
)

analyze_clicked = st.button("Analyze", type="primary")


def _get_groq_api_key() -> Optional[str]:
    try:
        return st.secrets["api_keys"]["groq"]
    except Exception:
        return None


def build_ai_prompt(ioc, ioc_type, knowledge_level, source_results):
    evidence_lines = []
    for source_name, result in source_results.items():
        evidence_lines.append(f"### {source_name}")
        evidence_lines.append(f"- Verdict: {result.get('source_verdict')}")
        evidence_lines.append(f"- Risk level: {result.get('risk_source')}")
        if result.get("error"):
            evidence_lines.append(f"- Error: {result.get('error')}")
        raw_data = result.get("raw_data") or {}
        if raw_data:
            evidence_lines.append(f"- Raw data: {json.dumps(raw_data, default=str)}")
        evidence_lines.append("")

    evidence_block = "\n".join(evidence_lines)

    level_instructions = {
        "Beginner": "Use simple, plain language. Briefly explain any cybersecurity terminology you use. Focus on what this practically means for the user, avoiding jargon where possible.",
        "Intermediate": "Use moderate technical detail. Explain the important indicators and use standard cybersecurity terminology, but keep explanations accessible.",
        "Expert": "Use precise technical threat-intelligence language. Provide a detailed interpretation of detection signals, your confidence reasoning, known limitations of the evidence, and any disagreement between sources.",
    }

    prompt = f"""You are a cybersecurity threat-intelligence analyst assistant.

You will be given evidence collected from multiple threat-intelligence
sources about a single indicator of compromise (IOC). Your job is to
produce a final, evidence-based assessment.

STRICT RULES:
- Do not invent facts that are not present in the supplied evidence.
- Base all conclusions only on the supplied evidence below.
- Clearly distinguish between what is evidence and what is your assumption/inference.
- Consider and note any disagreements between sources.
- Explicitly explain uncertainty where evidence is incomplete or unknown.
- Do NOT automatically label an IOC as malicious based on a single weak indicator.
- WHOIS privacy protection, incomplete registration data, or domain age alone
  are NOT sufficient grounds for a malicious or suspicious verdict.
- If a source returned an error or "unknown", treat it as missing evidence,
  not as a negative signal.

INDICATOR OF COMPROMISE
- IOC: {ioc}
- IOC type: {ioc_type}

USER KNOWLEDGE LEVEL: {knowledge_level}
{level_instructions.get(knowledge_level, level_instructions["Intermediate"])}

EVIDENCE FROM SOURCES:
{evidence_block}

RESPONSE FORMAT:
Return ONLY valid JSON (no markdown code fences, no commentary before or
after) matching exactly this structure:

{{
    "verdict": "SAFE | SUSPICIOUS | MALICIOUS | UNKNOWN",
    "risk_score": 0,
    "summary": "...",
    "key_findings": ["...", "..."],
    "ai_insight": "...",
    "recommended_action": "...",
    "confidence": 0
}}

Where:
- risk_score is an integer from 0 to 100.
- confidence is an integer from 0 to 100 representing your confidence in
  this assessment given the available evidence.
- key_findings is a list of short, specific bullet-style strings.
- ai_insight should be written at the {knowledge_level} level described above.
"""
    return prompt


def call_groq(prompt: str) -> Dict[str, Any]:
    api_key = _get_groq_api_key()
    if not api_key:
        return {"error": "Groq API key is missing from secrets."}

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": "openai/gpt-oss-20b",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        if response.status_code == 401:
            return {"error": "Groq API key is invalid or unauthorized."}
        if response.status_code == 429:
            return {"error": "Groq rate limit exceeded. Try again later."}
        if not response.ok:
            return {"error": f"Groq API returned HTTP {response.status_code}: {response.text[:300]}"}

        data = response.json()
        choices = data.get("choices", [])
        if not choices:
            return {"error": "Groq returned no response choices."}

        text = choices[0].get("message", {}).get("content", "").strip()
        if not text:
            return {"error": "Groq returned an empty response."}
        return {"text": text}

    except requests.exceptions.Timeout:
        return {"error": "Groq request timed out."}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to Groq (network error)."}
    except requests.exceptions.RequestException as exc:
        return {"error": f"Groq request failed: {exc}"}
    except Exception as exc:
        return {"error": f"Unexpected Groq error: {exc}"}


def parse_ai_json(text: str) -> Optional[Dict[str, Any]]:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
        cleaned = cleaned.strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                parsed = json.loads(cleaned[start : end + 1])
            except json.JSONDecodeError:
                return None
        else:
            return None

    required_keys = {"verdict", "risk_score", "summary", "key_findings", "ai_insight", "recommended_action", "confidence"}
    if not required_keys.issubset(parsed.keys()):
        return None
    return parsed


def run_sources(ioc: str, ioc_type: str) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for source_name, source_function in SOURCES.items():
        try:
            results[source_name] = source_function(ioc, ioc_type)
        except Exception as exc:
            results[source_name] = {
                "source_verdict": "unknown", "risk_source": "unknown",
                "raw_data": {}, "error": f"{source_name} failed unexpectedly: {exc}",
            }
    return results


def render_verdict_badge(verdict: str) -> str:
    css_class = VERDICT_BADGE_CLASS.get(verdict, "tl-badge-unknown")
    return f'<span class="tl-badge {css_class}">{verdict}</span>'


def render_source_badge(verdict: str) -> str:
    css_class = SOURCE_VERDICT_BADGE_CLASS.get(verdict, "tl-badge-unknown")
    return f'<span class="tl-badge {css_class}">{verdict.capitalize()}</span>'


def display_dashboard(ioc, ioc_type_label, ai_result):
    verdict = str(ai_result.get("verdict", "UNKNOWN")).upper()
    risk_score = ai_result.get("risk_score", 0)
    confidence = ai_result.get("confidence", 0)

    st.markdown("## Result Dashboard")
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown('<div class="tl-metric-label">IOC</div>', unsafe_allow_html=True)
        st.markdown(f"**{ioc}**")
    with col2:
        st.markdown('<div class="tl-metric-label">IOC Type</div>', unsafe_allow_html=True)
        st.markdown(f"**{ioc_type_label}**")
    with col3:
        st.markdown('<div class="tl-metric-label">Overall Verdict</div>', unsafe_allow_html=True)
        st.markdown(render_verdict_badge(verdict), unsafe_allow_html=True)
    with col4:
        st.markdown('<div class="tl-metric-label">Risk Score / Confidence</div>', unsafe_allow_html=True)
        st.markdown(f"**{risk_score}/100**  ·  confidence {confidence}/100")

    st.markdown("---")
    st.markdown("### Summary")
    st.write(ai_result.get("summary", "No summary provided."))

    st.markdown("### Key Findings")
    findings: List[str] = ai_result.get("key_findings") or []
    if findings:
        for finding in findings:
            st.markdown(f"- {finding}")
    else:
        st.caption("No key findings provided.")

    st.markdown("### AI Insight")
    st.write(ai_result.get("ai_insight", "No AI insight provided."))

    st.markdown("### Recommended Action")
    st.info(ai_result.get("recommended_action", "No recommendation provided."))


def display_source_results(source_results):
    st.markdown("## Source Results")
    for source_name, result in source_results.items():
        with st.container():
            st.markdown(f'<div class="tl-card">', unsafe_allow_html=True)
            col1, col2 = st.columns([2, 3])
            with col1:
                st.markdown(f"**{source_name}**")
            with col2:
                verdict = result.get("source_verdict", "unknown")
                risk = result.get("risk_source", "unknown")
                st.markdown(
                    f"{render_source_badge(verdict)} &nbsp; <span class='tl-metric-label'>Risk: {risk}</span>",
                    unsafe_allow_html=True,
                )
            if result.get("error"):
                st.warning(result["error"])
            raw_data = result.get("raw_data") or {}
            with st.expander("Raw Data"):
                if raw_data:
                    st.json(raw_data)
                else:
                    st.caption("No raw data available.")
            st.markdown("</div>", unsafe_allow_html=True)


if analyze_clicked:
    ioc_raw = (ioc_input or "").strip()

    if not ioc_raw:
        st.error("Please enter an IP address, domain, or URL to analyze.")
    elif not is_valid_ioc(ioc_raw, ioc_type):
        detected = detect_ioc_type(ioc_raw)
        st.error(
            f"'{ioc_raw}' does not look like a valid {ioc_type_label.lower()}. "
            + (f"It looks more like a **{detected}**." if detected != "unknown" else "Please check the value and try again.")
        )
    else:
        with st.spinner("Querying threat-intelligence sources..."):
            source_results = run_sources(ioc_raw, ioc_type)

        with st.spinner("Generating AI-powered analysis..."):
            prompt = build_ai_prompt(ioc_raw, ioc_type, knowledge_level, source_results)
            ai_response = call_groq(prompt)

        ai_result: Optional[Dict[str, Any]] = None
        if ai_response.get("error"):
            st.error(f"AI analysis failed: {ai_response['error']}")
        else:
            ai_result = parse_ai_json(ai_response["text"])
            if ai_result is None:
                st.error("AI analysis returned an unexpected format and could not be parsed. Showing raw source results below.")

        if ai_result:
            display_dashboard(ioc_raw, ioc_type_label, ai_result)
            st.markdown("---")

        display_source_results(source_results)
else:
    st.markdown(
        '<div class="tl-card">Select an IOC type and knowledge level in the '
        "sidebar, enter an indicator above, then click <b>Analyze</b>.</div>",
        unsafe_allow_html=True,
    )
