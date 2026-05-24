<div align="center">

# Kaavish

### Automated Adversarial Red Teaming for Large Language Model Systems

*Systematic. Reproducible. Evidence-based.*

![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-red?style=flat)
![MITRE ATLAS](https://img.shields.io/badge/MITRE-ATLAS%20Aligned-blue?style=flat)

</div>

---

## Overview

Kaavish is a backend-first, API-driven automated red teaming platform for AI systems deployed in production. It operationalises the adversarial attack taxonomy defined by **OWASP LLM Top 10 (2025)**, **MITRE ATLAS**, and peer-reviewed research from NeurIPS, USENIX Security, and ICLR — translating theoretical vulnerability classes into concrete, verifiable, reproducible exploit chains.

Traditional penetration testing pipelines (Nmap, Metasploit, Burp Suite) operate on deterministic software artefacts. LLMs and agent systems introduce a fundamentally non-deterministic, context-sensitive attack surface: adversarial inputs do not exploit memory boundaries or packet fields — they exploit the model's trained probability distributions, instruction-following behaviour, and tool-calling logic. Kaavish was built specifically for this surface.

The platform is not a compliance questionnaire or a static analysis tool. It executes live adversarial payloads against running systems, verifies exploitability through observable response signals, and produces evidence-backed reports with reproducible proof-of-concept demonstrations.

---

## The Threat Landscape

The deployment of LLM-based systems has outpaced the development of security tooling designed for them. Recent empirical measurements illustrate the scale of the problem:

- **74% of LLM-integrated applications** are susceptible to at least one form of prompt injection in default configurations (Greshake et al., 2023)
- **Indirect prompt injection** — where malicious instructions are embedded in documents, web pages, or tool outputs processed by an agent — represents an attack surface with no equivalent in traditional software security
- **Jailbreak transferability** is high: adversarial suffixes found on open-weight models transfer to closed-weight production systems (Zou et al., 2023) with non-trivial success rates
- **Training data extraction** has been demonstrated empirically on GPT-2 and GPT-3.5, recovering verbatim memorised sequences including PII (Carlini et al., 2021, 2023)
- The **OWASP LLM Top 10 (2025)** explicitly names prompt injection as the highest-severity vulnerability class for LLM applications

The security industry has not yet produced a standardised automated toolchain for testing these properties. Kaavish fills that gap.

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        Kaavish API (FastAPI)                   │
│                                                                │
│   POST /scans          → Enqueue scan, return scan_id          │
│   GET  /scans/{id}/status   → Poll scan state                  │
│   GET  /scans/{id}/results  → Full findings JSON               │
│   GET  /scans/{id}/report.pdf → Evidence report                │
└──────────────────────────┬─────────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │     Target Profiler     │
              │   (core/scanner.py)     │
              │                         │
              │  • Input schema probe   │
              │  • Model fingerprint    │
              │  • Framework detection  │
              │  • Tool/RAG capability  │
              └────────────┬────────────┘
                           │  TargetProfile
              ┌────────────▼────────────┐
              │    Attack Executor      │
              │   (core/executor.py)    │
              │                         │
              │  asyncio.gather()       │
              │  All attacks concurrent │
              └──┬──────┬──────┬────────┘
                 │      │      │
    ┌────────────▼┐ ┌───▼────┐ ┌▼──────────────┐ ┌────────────┐
    │   Prompt    │ │ Jail-  │ │     Data       │ │   Agent    │
    │  Injection  │ │ break  │ │  Extraction   │ │  Hijack    │
    │  (10 vars)  │ │(6 vars)│ │   (6 vars)    │ │  (7 vars)  │
    └─────────────┘ └────────┘ └───────────────┘ └────────────┘
                           │
              ┌────────────▼────────────┐
              │    Report Generator     │
              │   (core/reporter.py)    │
              │                         │
              │  Markdown + PDF         │
              │  Severity scoring       │
              │  Remediation guidance   │
              └─────────────────────────┘
```

### Design Decisions

**Concurrent execution via `asyncio.gather`**
All attack classes execute concurrently against the target. This is intentional: sequential execution would allow rate-limiting or session-state changes between tests to mask vulnerabilities. Concurrency reflects realistic adversarial conditions.

**Profile-driven attack selection**
The profiler runs before any attacks. Agent-specific attacks (tool enumeration, SSRF via agent, cross-tool exfiltration chains) only execute if the profiler detects tool-calling capability. This prevents false positives and reduces noise on non-agent targets.

**Verify-before-report**
Every attack class verifies the exploit is real before recording a finding. A response containing restricted content is only classified as a finding if it matches specific, pre-defined exploitation indicators. This minimises false positive rates.

**Pluggable attack interface**
Every attack inherits from `BaseAttack` and exposes a uniform `async execute() -> AttackResult` interface. Adding a new attack class requires only implementing `execute()` — the executor, reporter, and API require no modification.

---

## Attack Coverage

Kaavish implements attacks across four primary vulnerability classes, aligned to the OWASP LLM Top 10 (2025) taxonomy.

### LLM01 — Prompt Injection (`attacks/prompt_injection.py`)

Direct prompt injection exploits the fundamental architectural property that LLMs process system instructions and user inputs within a shared token sequence. When the model cannot reliably distinguish between instruction-carrying and data-carrying tokens, an adversarial user can override, extend, or replace the application's system prompt.

| Variant | Technique | Reference |
|---------|-----------|-----------|
| System Prompt Extraction | Direct verbatim extraction request | Perez & Ribeiro (2022) |
| System Instruction Override | Role replacement via DAN-class injection | Wei et al. (2023) |
| Delimiter Confusion | Injecting synthetic end-of-prompt markers | Greshake et al. (2023) |
| Base64-Encoded Smuggling | Encoding bypasses lexical input filters | Branch et al. (2022) |
| Social Engineering Injection | False authority claims from within user turn | — |
| Fake System Message | Injecting `[SYSTEM UPDATE]` tags | Greshake et al. (2023) |
| Context Summarisation Leakage | Requesting self-summary of instructions | — |
| Template Injection (Jinja2) | `{{7*7}}` evaluation in LangChain pipelines | — |
| HTML/XML Tag Injection | `<system>` tag misinterpretation | — |
| Multilingual Override | Safety restriction bypass via non-English | Yong et al. (2023) |

### LLM02 / LLM07 — Jailbreaking & Safety Bypass (`attacks/jailbreaks.py`)

Jailbreak attacks exploit misalignment between a model's safety training and its instruction-following training. When the two objectives conflict, safety training fails non-uniformly across prompt formulations. All jailbreak tests are validated against a baseline: the target must refuse the raw probe before a jailbreak attempt is credited as a bypass.

| Variant | Technique | Reference |
|---------|-----------|-----------|
| DAN Persona | Alternate identity adoption | Wei et al. (2023) |
| Hypothetical Framing | Fictional context lowers safety threshold | Wei et al. (2023) |
| Temporal Roleplay | Alternate-reality framing | — |
| False Authority | Professional context social engineering | — |
| Completion Trap | Partial-sentence completion sidesteps safety check on input | — |
| Opposite Day | Logical contradiction manipulation | — |

Additionally: targets with **no safety guardrails** are classified as Critical findings without requiring a jailbreak, per OWASP LLM06 (Excessive Agency).

### LLM02 — Sensitive Information Disclosure (`attacks/data_extraction.py`)

Data extraction attacks target the model's ability to surface memorised training data, injected context, or connected data store contents. All findings are verified via regex matching against real PII patterns before being recorded — the system does not flag theoretical exposure without observable evidence.

Detected PII classes: email addresses, US/IN phone numbers, credit card numbers, US SSNs, IPv4 addresses, API keys (OpenAI `sk-`, AWS `AKIA`, Stripe `sk_live`).

| Variant | Target | Reference |
|---------|--------|-----------|
| Training Data Extraction | Memorised PII from training corpus | Carlini et al. (2021) |
| Context Window Extraction | PII surfaced from conversation context | — |
| RAG Data Store Extraction | PII retrieved from connected knowledge base | — |
| API Key / Secret Extraction | Credentials injected into agent context | — |
| Knowledge Base Dump | Verbatim reproduction of internal documents | — |
| Session Context Extraction | User session data injected as personalisation context | — |

### LLM06 — Excessive Agency / Agent Hijacking (`attacks/agent_hijack.py`)

Agent hijacking attacks target the expanded trust surface introduced by agentic AI systems with tool access. An agent that can send emails, query databases, or browse the web introduces attack chains with no equivalent in passive LLM deployments. These attacks only execute when the profiler detects tool-calling capability.

| Variant | Target | CVE / Reference |
|---------|--------|-----------------|
| Tool Enumeration | Exposes full tool inventory and schemas | OWASP LLM07 |
| Cross-Tool Exfiltration | File search → email exfiltration chain | Greshake et al. (2023) |
| SSRF via Agent Web Tool | `169.254.169.254` metadata endpoint access | SSRF (CWE-918) |
| Unauthorised DB Query | Raw SQL execution via agent query tool | SQLi (CWE-89) |
| Indirect Prompt Injection | Malicious content in tool output hijacks agent | Greshake et al. (2023) |
| Privilege Escalation | Social engineering into elevated permissions | OWASP LLM06 |
| Environment Variable Extraction | Runtime secrets exposed via LLM context | — |

---

## Installation

**Prerequisites:** Python 3.12+, Docker, Docker Compose

```bash
git clone https://github.com/your-org/kaavish
cd kaavish
cp .env.example .env
docker compose up --build
```

The API is available at `http://localhost:8000`. Interactive documentation at `http://localhost:8000/docs`.

### Running Without Docker

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

---

## Usage

### Submit a Scan

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_endpoint": "https://your-ai-product.com/api/chat",
    "headers": {
      "Authorization": "Bearer YOUR_API_KEY"
    }
  }'
```

Response:
```json
{
  "scan_id": "3f2a1b4c-...",
  "status": "queued",
  "message": "Scan started. Poll /scans/3f2a1b4c-.../status for progress."
}
```

### Poll for Completion

```bash
curl http://localhost:8000/scans/3f2a1b4c-.../status
```

### Retrieve Full Results

```bash
curl http://localhost:8000/scans/3f2a1b4c-.../results
```

### Download PDF Report

```bash
curl -o report.pdf http://localhost:8000/scans/3f2a1b4c-.../report.pdf
```

### Force Agent Attack Mode

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_endpoint": "https://your-agent.com/api/run",
    "force_agent_attacks": true
  }'
```

---

## Report Format

Every scan produces a structured report with four sections per finding:

1. **Description** — mechanism of vulnerability and its security implications
2. **Proof of Concept** — the exact payload that triggered the vulnerability, reproducible verbatim
3. **Evidence** — the raw (PII-redacted) target response confirming exploitability
4. **Remediation** — specific, actionable remediation steps with urgency classification

Severity levels follow the CVSS v3.1 qualitative scale: Critical / High / Medium / Low.

---

## Responsible Disclosure

Kaavish is designed for **authorised security testing only**. Before scanning any system:

1. Obtain written authorisation from the system owner
2. Scope the engagement explicitly to the target endpoint
3. Handle all findings as confidential until remediated
4. Follow responsible disclosure practices for third-party systems

The attack payloads included in this platform are sourced from published academic research and publicly documented attack taxonomies. They are implemented here for defensive purposes — to enable organisations to identify and remediate vulnerabilities in their own systems before adversarial actors discover them.

---

## Repository Structure

```
kaavish/
├── about.md                    # Product vision
├── README.md                   # This document
├── RESEARCH.md                 # Deep technical research notes
├── docker-compose.yml
├── .env.example
└── backend/
    ├── main.py                 # FastAPI application
    ├── requirements.txt
    ├── Dockerfile
    ├── attacks/
    │   ├── base.py             # BaseAttack abstract class + data models
    │   ├── prompt_injection.py # LLM01 — 10 direct injection variants
    │   ├── jailbreaks.py       # LLM02/07 — 6 safety bypass techniques
    │   ├── data_extraction.py  # LLM02 — PII + secret extraction
    │   └── agent_hijack.py     # LLM06 — 7 agent hijacking vectors
    └── core/
        ├── scanner.py          # Target profiling (model, framework, capabilities)
        ├── executor.py         # Concurrent attack orchestration
        └── reporter.py         # Markdown + PDF report generation
```

---

## References

1. Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. arXiv:2302.12173.

2. Zou, A., Wang, Z., Kolter, J. Z., & Fredrikson, M. (2023). *Universal and Transferable Adversarial Attacks on Aligned Language Models*. arXiv:2307.15043.

3. Wei, A., Haghtalab, N., & Steinhardt, J. (2023). *Jailbroken: How Does LLM Safety Training Fail?* NeurIPS 2023.

4. Carlini, N., Tramer, F., Wallace, E., Jagielski, M., Herbert-Voss, A., Lee, K., Roberts, A., Brown, T., Song, D., Erlingsson, U., Oprea, A., & Raffel, C. (2021). *Extracting Training Data from Large Language Models*. USENIX Security 2021.

5. Perez, F., & Ribeiro, I. (2022). *Ignore Previous Prompt: Attack Techniques For Language Models*. arXiv:2211.09527.

6. Yong, Z. X., Menghini, C., & Bach, S. H. (2023). *Low-Resource Languages Jailbreak GPT-4*. NeurIPS 2023 SoLaR Workshop.

7. OWASP. (2025). *OWASP Top 10 for Large Language Model Applications*. https://owasp.org/www-project-top-10-for-large-language-model-applications/

8. MITRE. (2023). *ATLAS: Adversarial Threat Landscape for AI Systems*. https://atlas.mitre.org/

9. NIST. (2023). *AI Risk Management Framework (AI RMF 1.0)*. NIST AI 100-1.

10. Carlini, N., Ippolito, D., Jagielski, M., Lee, K., Tramer, F., & Zhang, C. (2023). *Quantifying Memorization Across Neural Language Models*. ICLR 2023.

---

*Kaavish — we break your AI before someone else does.*
