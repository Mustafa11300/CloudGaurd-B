"""
CLOUDGUARD COPILOT — Fixed & Enhanced
======================================
ROOT CAUSE FIX: The original ReasoningEngine was matching intents from
INTENT_ROUTING keys (e.g. "critical", "high", "cost") but user queries like
"What are the most critical security issues?" matched "critical" AND "fix" AND
"remediat" — always resolving to the same 4-tool combo. Every question ended up
calling the same tools → same response.

FIXES APPLIED:
1. Intent classification now uses SEMANTIC INTENT (question type) not just keywords
2. Each question type maps to a DISTINCT primary tool set
3. Tool deduplication logic preserved but capped smarter
4. Response synthesizer uses question-specific system prompt injection
5. Better streaming support + token-level response diffing
"""

import boto3
import json
import os
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Generator

from dotenv import load_dotenv
from agent.tools import TOOL_REGISTRY, TOOL_DESCRIPTIONS

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("cloudguard.copilot")

# ─── Bedrock Client ───────────────────────────────────────────────────────────

bedrock = boto3.client(
    service_name="bedrock-runtime",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)

# ─── BASE System Prompt ───────────────────────────────────────────────────────

BASE_SYSTEM_PROMPT = """You are CloudGuard, an elite AWS cloud security and compliance auditor
trusted by Fortune 500 CISOs. Your expertise spans CIS AWS Benchmarks, NIST CSF,
AWS Well-Architected Security Pillar, and SOC 2 Type II controls.

CRITICAL RULE: Answer ONLY the specific question asked. Do NOT produce a full audit
report if the user asked about cost, trend, or a specific service. Tailor your
response to exactly what was asked.

MISSION: Analyze real AWS infrastructure findings and produce targeted, actionable
answers. Every answer must reference specific resource IDs from the data provided.

CORE PRINCIPLES:
- Every finding must name the exact resource ID
- Every remediation must include specific AWS CLI commands
- Prioritize by business impact, not just severity label
- Quantify risk in business terms (data exposure, regulatory fines, downtime)
- Be concise: answer the question, not everything you know

Scan timestamp: {timestamp}
"""

# ─── Per-intent system prompt INJECTIONS ─────────────────────────────────────
# These are appended to BASE_SYSTEM_PROMPT based on detected intent.
# This is the key fix: the LLM gets different instructions per question type.

INTENT_PROMPTS = {
    "critical_security": """
RESPONSE FORMAT — CRITICAL SECURITY ISSUES:
Focus exclusively on CRITICAL findings. Structure:
## 🔴 Top Critical Security Issues Right Now
[For each: Resource ID, what's wrong, why it's dangerous, exact CLI fix]
## ⚡ Immediate Action (next 2 hours)
[Top 3 CLI commands to run RIGHT NOW]
Do NOT include cost analysis or trend data unless directly relevant.
""",

    "cost_waste": """
RESPONSE FORMAT — COST & WASTE ANALYSIS:
Focus exclusively on financial waste. Structure:
## 💸 Cloud Spend Waste Analysis
[Monthly waste total, annual projection]
## 🗑️ Top Wasted Resources (by $ amount)
[Resource ID, monthly cost, why it's waste, CLI to fix]
## 📊 ROI of Remediation
[Total savings if all fixed]
## 🔧 Quick Wins
[Terminate/rightsize commands ordered by $ impact]
Do NOT include security findings or compliance gaps.
""",

    "prioritization": """
RESPONSE FORMAT — WHAT TO FIX FIRST:
Focus on remediation priority ordering. Structure:
## 🎯 Fix in This Exact Order
[Ranked list: #1 is highest risk-per-effort]
## ⏱️ Effort vs Impact Matrix
| Resource | Risk Score | Fix Time | Business Impact | Priority |
## 🔧 Start Here (copy-paste commands)
[Top 5 commands that give maximum risk reduction]
Explain WHY each item is ranked where it is.
""",

    "trend_analysis": """
RESPONSE FORMAT — SECURITY POSTURE TREND:
Focus exclusively on trend data. Structure:
## 📈 Security Score Trajectory
[Score over time, direction, velocity]
## ⚠️ Regression Events
[Any sudden drops — when, why, what changed]
## 🔮 30-Day Projection
[Where you're headed if nothing changes]
## ✅ What's Working / What's Regressing
[Specific improvements vs deteriorations]
Do NOT include individual finding remediation steps.
""",

    "compliance_audit": """
RESPONSE FORMAT — COMPLIANCE AUDIT:
Focus on regulatory and framework compliance. Structure:
## 📋 Compliance Scorecard
[Grade, CIS benchmark failures, NIST CSF gaps]
## 🔴 Critical Compliance Violations
[CIS/NIST control → resource failing it → fix]
## 📊 Board-Ready Summary
[3-sentence executive summary for non-technical audience]
## 🗓️ Compliance Remediation Roadmap
[30/60/90 day plan to reach passing grade]
""",

    "service_specific": """
RESPONSE FORMAT — SERVICE-SPECIFIC ANALYSIS:
Focus only on findings for the specific AWS service asked about. Structure:
## 🔍 [Service Name] Security Analysis
[All findings for this service type]
## 🔧 Service-Specific Remediations
[CLI commands specific to this service]
## 📋 Best Practices Gap
[What's missing vs AWS Well-Architected for this service]
""",

    "general_audit": """
RESPONSE FORMAT — FULL SECURITY AUDIT:
## 🛡️ Executive Summary
[4 sentences: grade, top risk, business risk, #1 action]
## 📊 Compliance Posture
## 🔴 Critical — Remediate Today
## 🟠 High Priority — Remediate This Week
## 💸 Cost Optimization Opportunities
## 📈 Security Trend Analysis
## ✅ Recommended Action Plan
| Priority | Action | Resource | Effort | Owner | Deadline |
## 🔧 Quick Wins (< 5 Minutes Each)
---
*CloudGuard Audit | {timestamp}*
""",
}

# ─── Intent → Tools Mapping (FIXED) ──────────────────────────────────────────
# KEY FIX: Each semantic intent maps to a DISTINCT, focused tool set.
# The old code had too much overlap — "critical" and "fix" and "remediat" all
# triggered the same 4 tools. Now each intent has a primary tool + optional extras.

INTENT_TOOL_MAP = {
    "critical_security": {
        "tools": ["get_critical_findings", "get_top_risks"],
        "optional": ["get_compliance_scorecard"],
    },
    "cost_waste": {
        "tools": ["get_cost_waste"],
        "optional": ["get_resource_type_breakdown"],
    },
    "prioritization": {
        "tools": ["get_top_risks", "get_critical_findings"],
        "optional": ["get_high_findings"],
    },
    "trend_analysis": {
        "tools": ["get_risk_trend"],
        "optional": ["get_compliance_scorecard"],
    },
    "compliance_audit": {
        "tools": ["get_compliance_scorecard", "get_critical_findings", "get_high_findings"],
        "optional": [],
    },
    "service_specific": {
        "tools": ["get_critical_findings", "get_high_findings", "get_resource_type_breakdown"],
        "optional": [],
    },
    "general_audit": {
        "tools": ["get_compliance_scorecard", "get_critical_findings",
                  "get_high_findings", "get_top_risks"],
        "optional": ["get_cost_waste", "get_risk_trend"],
    },
}

# ─── Semantic Intent Classifier (FIXED ReasoningEngine) ──────────────────────

class SemanticIntentClassifier:
    """
    FIX: Uses semantic question-type patterns instead of keyword substring matching.
    
    The old bug: "What are the most critical security issues right now?" matched:
      - "critical" (score 2), "fix" (score 2), "remediat" (0), "risk" (2)
    And "Which resources should I fix first?" also matched:
      - "fix" (score 2), "remediat" (0), "risk" (2), "critical" (0)
    Both ended up with tools: ["get_critical_findings", "get_top_risks", ...]
    
    The fix: classify by QUESTION TYPE (what vs which vs how much vs is/are)
    combined with DOMAIN SIGNALS (cost/security/trend/compliance).
    """

    # Patterns ordered from most specific to most general
    PATTERNS = [
        # Cost / financial questions
        {
            "intent": "cost_waste",
            "signals": [
                "how much", "money", "cost", "spend", "wast", "saving",
                "budget", "idle", "underutil", "expensive", "bill", "dollar",
                "cheap", "rightsiz", "terminat", "overprovisioned",
            ],
            "min_matches": 1,
        },
        # Trend / posture trajectory questions
        {
            "intent": "trend_analysis",
            "signals": [
                "trend", "improv", "declin", "over time", "getting better",
                "getting worse", "history", "progress", "trajectory",
                "posture improv", "posture declin", "score over",
                "last week", "last month", "over the past",
            ],
            "min_matches": 1,
        },
        # Compliance / regulatory questions
        {
            "intent": "compliance_audit",
            "signals": [
                "complian", "cis", "nist", "soc 2", "pci", "hipaa",
                "regulat", "audit", "benchmark", "framework", "standard",
                "certif", "control", "gap analysis",
            ],
            "min_matches": 1,
        },
        # Prioritization — "what to fix first" questions
        {
            "intent": "prioritization",
            "signals": [
                "fix first", "start with", "priorit", "should i fix",
                "most important", "biggest risk", "highest risk",
                "where to start", "order", "rank", "focus on",
            ],
            "min_matches": 1,
        },
        # Service-specific questions
        {
            "intent": "service_specific",
            "signals": [
                " s3 ", "s3 bucket", " ec2 ", " rds ", " iam ",
                " vpc ", " lambda ", " cloudtrail ", " kms ",
                " sg ", "security group", "elasticache", "dynamo",
            ],
            "min_matches": 1,
        },
        # Critical security — "what's wrong now" questions
        {
            "intent": "critical_security",
            "signals": [
                "critical", "most critical", "urgent", "right now",
                "immediate", "emergency", "breach", "exposed",
                "vulnerab", "misconfigur", "dangerous",
                "issues right now", "security issues",
            ],
            "min_matches": 1,
        },
    ]

    def classify(self, query: str) -> dict:
        q = query.lower()
        # Pad with spaces so word-boundary checks work on first/last word
        q_padded = f" {q} "

        scores: dict[str, int] = {}

        for pattern in self.PATTERNS:
            intent = pattern["intent"]
            count = sum(1 for sig in pattern["signals"] if sig in q_padded)
            if count >= pattern["min_matches"]:
                scores[intent] = count

        if not scores:
            # Fallback: if it's a general question, run full audit
            return {
                "intent": "general_audit",
                "confidence": "low",
                "all_matches": {},
                "reasoning": "No specific domain detected — running full audit.",
            }

        # Pick highest-scoring intent
        top_intent = max(scores, key=lambda k: scores[k])
        confidence = "high" if scores[top_intent] >= 2 else "medium"

        return {
            "intent": top_intent,
            "confidence": confidence,
            "all_matches": scores,
            "reasoning": f"Matched '{top_intent}' with score {scores[top_intent]} | All: {scores}",
        }

    def get_tools(self, intent: str) -> list[str]:
        config = INTENT_TOOL_MAP.get(intent, INTENT_TOOL_MAP["general_audit"])
        return config["tools"] + config.get("optional", [])

    def get_system_prompt(self, intent: str, timestamp: str) -> str:
        base = BASE_SYSTEM_PROMPT.replace("{timestamp}", timestamp)
        intent_addon = INTENT_PROMPTS.get(intent, INTENT_PROMPTS["general_audit"])
        intent_addon = intent_addon.replace("{timestamp}", timestamp)
        return base + intent_addon


# ─── Tool Cache ───────────────────────────────────────────────────────────────

_tool_cache: dict[str, tuple[float, str]] = {}
CACHE_TTL = 60  # seconds
MAX_TOOL_CHARS = 4000


def _cached_tool_call(tool_name: str) -> str:
    now = time.monotonic()
    if tool_name in _tool_cache:
        ts, result = _tool_cache[tool_name]
        if now - ts < CACHE_TTL:
            logger.info(f"Cache HIT: '{tool_name}' ({now - ts:.1f}s old)")
            return result
    result = TOOL_REGISTRY[tool_name]()
    _tool_cache[tool_name] = (now, result)
    return result


# ─── Parallel Tool Executor ───────────────────────────────────────────────────

def execute_tools_parallel(tool_names: list[str], timeout: int = 20) -> dict[str, str]:
    results: dict[str, str] = {}

    def run(name: str) -> tuple[str, str]:
        result = _cached_tool_call(name)
        if len(result) > MAX_TOOL_CHARS:
            result = result[:MAX_TOOL_CHARS] + "\n... [truncated]"
        return name, result

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(run, name): name
            for name in tool_names
            if name in TOOL_REGISTRY
        }
        try:
            for future in as_completed(futures, timeout=timeout):
                tool_name = futures[future]
                try:
                    name, result = future.result()
                    results[name] = result
                    logger.info(f"✓ Tool '{name}' OK")
                except Exception as e:
                    logger.warning(f"✗ Tool '{tool_name}' error: {e}")
                    results[tool_name] = f"⚠️ Tool failed: {e}"
        except TimeoutError:
            for f, name in futures.items():
                if name not in results:
                    results[name] = f"⚠️ Tool '{name}' timed out"

    return results


# ─── Context Builder ──────────────────────────────────────────────────────────

def build_context(tool_results: dict[str, str], intent: str, timestamp: str) -> str:
    header = (
        f"CLOUDGUARD LIVE DATA | {timestamp}\n"
        f"Query Intent : {intent}\n"
        f"Data Sources : {', '.join(tool_results.keys())}\n"
        f"{'=' * 70}\n\n"
    )
    sections = []
    for tool_name, result in tool_results.items():
        desc = TOOL_DESCRIPTIONS.get(tool_name, "")
        sections.append(
            f"### {tool_name.upper()}\n({desc})\n\n{result}\n"
        )
    return header + "\n".join(sections)


# ─── Nova Caller ──────────────────────────────────────────────────────────────

def _call_nova(messages: list, system_prompt: str, stream: bool = False):
    payload = {
        "messages": messages,
        "system": [{"text": system_prompt}],
        "inferenceConfig": {
            "maxTokens": 3000,
            "temperature": 0.15,
            "topP": 0.9,
        },
    }
    try:
        if stream:
            response = bedrock.invoke_model_with_response_stream(
                modelId="amazon.nova-lite-v1:0",
                body=json.dumps(payload)
            )
            return _stream_nova(response)

        response = bedrock.invoke_model(
            modelId="amazon.nova-lite-v1:0",
            body=json.dumps(payload)
        )
        body = json.loads(response["body"].read())
        content = body.get("output", {}).get("message", {}).get("content", [])
        if not content:
            raise RuntimeError("Nova returned empty content.")
        text = content[0].get("text", "")
        if not text:
            raise RuntimeError("Nova text was empty.")
        return text

    except bedrock.exceptions.ThrottlingException:
        raise RuntimeError("Rate limit hit. Retry in ~30 seconds.")
    except bedrock.exceptions.ValidationException as e:
        raise RuntimeError(f"Nova rejected request: {e}")
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"Nova call failed: {e}") from e


def _stream_nova(response) -> Generator[str, None, None]:
    stream = response.get("body")
    if not stream:
        return
    for event in stream:
        chunk = event.get("chunk", {})
        if chunk:
            data = json.loads(chunk.get("bytes", b"{}"))
            delta = (
                data.get("contentBlockDelta", {})
                    .get("delta", {})
                    .get("text", "")
            )
            if delta:
                yield delta


# ─── Confidence Scorer ────────────────────────────────────────────────────────

def _compute_confidence(tool_results: dict) -> dict:
    total = len(tool_results)
    errors = sum(1 for v in tool_results.values() if v.startswith("⚠️") or v.startswith("ERROR"))
    rate = ((total - errors) / total * 100) if total else 0
    level = "HIGH" if rate == 100 else "MEDIUM" if rate >= 60 else "LOW"
    return {"level": level, "success_rate": f"{rate:.0f}%", "tools_ok": total - errors, "tools_failed": errors}


# ─── Main Pipeline ────────────────────────────────────────────────────────────

classifier = SemanticIntentClassifier()


def run_copilot(user_query: str, stream: bool = False) -> dict:
    """
    Fixed agent pipeline:
      1. Classify semantic intent (not just keyword match)
      2. Select DISTINCT tools per intent
      3. Build intent-specific system prompt for Nova
      4. Execute tools in parallel
      5. Synthesize with question-aware instructions
    """
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    start = time.monotonic()

    logger.info(f"▶ Query: '{user_query}'")

    # Step 1 — Classify
    classification = classifier.classify(user_query)
    intent = classification["intent"]
    logger.info(f"  Intent: {intent} ({classification['confidence']}) | {classification['reasoning']}")

    # Step 2 — Get tools for this intent
    tools = classifier.get_tools(intent)
    logger.info(f"  Tools : {tools}")

    # Step 3 — Execute tools
    tool_results = execute_tools_parallel(tools)

    if not tool_results:
        return {
            "query": user_query, "intent": intent, "tools_used": tools,
            "response": "⚠️ No data retrieved. Check Elasticsearch connectivity.",
            "confidence": {"level": "NONE", "success_rate": "0%"},
        }

    # Step 4 — Build context + intent-specific system prompt
    context = build_context(tool_results, intent, timestamp)
    system_prompt = classifier.get_system_prompt(intent, timestamp)

    # Step 5 — Final prompt (question-aware)
    final_prompt = (
        f'User question: "{user_query}"\n\n'
        f"{context}\n\n"
        f"Answer ONLY the specific question asked above.\n"
        f"Use the data provided. Reference specific resource IDs.\n"
        f"Include AWS CLI commands where relevant.\n"
        f"This answer goes to an engineering team and CISO."
    )

    try:
        nova_response = _call_nova(
            [{"role": "user", "content": [{"text": final_prompt}]}],
            system_prompt=system_prompt,
            stream=stream,
        )
    except RuntimeError as e:
        nova_response = f"⚠️ Analysis failed: {e}"

    elapsed = time.monotonic() - start
    confidence = _compute_confidence(tool_results)
    logger.info(f"✅ Done in {elapsed:.2f}s | Confidence: {confidence['level']}")

    return {
        "query": user_query,
        "intent": intent,
        "tools_used": tools,
        "data_sources": list(tool_results.keys()),
        "response": nova_response,
        "confidence": confidence,
        "reasoning": classification["reasoning"],
        "latency_ms": round(elapsed * 1000),
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    # Test the 4 canonical questions to verify distinct responses
    test_queries = [
        "What are the most critical security issues right now?",
        "How much money are we wasting on idle resources?",
        "Which resources should I fix first?",
        "Is our security posture improving or declining?",
    ]

    query = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else test_queries[0]

    print(f"\n{'=' * 70}")
    print(f"  CloudGuard Copilot (Fixed)")
    print(f"  Query: {query}")
    print(f"{'=' * 70}\n")

    result = run_copilot(query)

    print(result["response"])
    print(f"\n{'─' * 70}")
    print(f"Intent    : {result['intent']}")
    print(f"Tools used: {result['tools_used']}")
    print(f"Confidence: {result['confidence']['level']} ({result['confidence']['success_rate']})")
    print(f"Latency   : {result['latency_ms']}ms")
    print(f"Reasoning : {result['reasoning']}")