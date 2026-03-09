"""
CLOUD SECURITY COPILOT AGENT
==============================
This is the main AI agent. It uses Amazon Nova 2 Lite to:
1. Understand the user's question
2. Decide which tools to call
3. Reason over the tool results
4. Generate a clear, business-focused answer

🔦 LOGIC FOCUS: The multi-step reasoning loop is the key differentiator.
The agent doesn't just call one tool — it chains calls together, building
context progressively before synthesizing a final answer.

This mimics how a real security analyst would investigate: gather data,
correlate findings, then write a summary recommendation.
"""

import boto3
import json
import os
from dotenv import load_dotenv
from agent.tools import TOOL_REGISTRY

load_dotenv()

# Connect to Amazon Bedrock (the service that hosts Nova)
bedrock = boto3.client(
    service_name="bedrock-runtime",
    region_name=os.getenv("AWS_REGION", "us-east-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

SYSTEM_PROMPT = """You are CloudGuard, an expert cloud security and cost optimization analyst.
You have access to tools that query a real-time Elasticsearch database of cloud resources.

YOUR ANALYSIS APPROACH:
1. ALWAYS fetch data before making claims — never guess
2. For security questions: get critical findings → get high findings → get trend → synthesize
3. For cost questions: get cost waste → get resource breakdown → calculate ROI
4. For "what to fix first": get top risks → prioritize by (severity × business impact) → list top 3
5. ALWAYS explain WHY something is risky in business terms, not just technical terms
6. ALWAYS end recommendations with a priority-ordered action list

YOUR TONE:
- Direct and actionable, like a trusted security advisor
- Use business language, not just technical jargon
- Quantify impact where possible (dollars, breach probability)
- Be honest about what you don't know

AVAILABLE TOOLS:
- get_critical_findings: All CRITICAL severity security issues
- get_high_findings: All HIGH severity issues
- get_cost_waste: Underutilized resources wasting money
- get_risk_trend: How security posture changed over time
- get_top_risks: Top 5 highest-risk resources right now
- get_resource_type_breakdown: Which resource types have most issues

FORMAT your response as:
## Summary
[2-3 sentence overview]

## Key Findings
[Specific findings with business impact]

## Priority Actions
1. [Most urgent — do today]
2. [Important — do this week]
3. [Should do — do this month]
"""


def call_nova(messages: list) -> str:
    """
    Sends messages to Amazon Nova 2 Lite and gets a response.

    Nova 2 Lite is a "reasoning model" — it doesn't just answer,
    it thinks through the problem step by step.
    """
    response = bedrock.invoke_model(
        modelId="amazon.nova-lite-v1:0",
        body=json.dumps({
            "messages": messages,
            "system": [{"text": SYSTEM_PROMPT}],
            "inferenceConfig": {
                "maxTokens": 2000,
                "temperature": 0.3  # Low temperature = more consistent, less creative
            }
        })
    )

    body = json.loads(response["body"].read())
    return body["output"]["message"]["content"][0]["text"]


def run_copilot(user_query: str) -> dict:
    """
    MAIN AGENT LOOP
    ================
    This is the multi-step reasoning pipeline.

    Step 1: Ask Nova which tools to call based on the query
    Step 2: Execute those tools against Elasticsearch
    Step 3: Feed the tool results back to Nova
    Step 4: Nova synthesizes a final answer

    🔦 LOGIC FOCUS: The agent decides what to look up based on the question.
    This is "context-aware" because different questions trigger different tool chains.
    """

    print(f"\n🤖 Processing query: '{user_query}'")

    # Step 1: Let Nova plan which tools to use
    planning_prompt = f"""
    User question: "{user_query}"

    Based on this question, which of these tools should I call to gather the right data?
    Available tools: {list(TOOL_REGISTRY.keys())}

    Respond with ONLY a JSON array of tool names, like: ["get_critical_findings", "get_cost_waste"]
    Choose 2-4 tools that are most relevant to answering this question.
    """

    planning_response = call_nova([{"role": "user", "content": [{"text": planning_prompt}]}])

    # Parse tool names from Nova's response
    try:
        # Extract JSON from response
        start = planning_response.find("[")
        end = planning_response.rfind("]") + 1
        tool_names = json.loads(planning_response[start:end])
    except:
        # Fallback: use default tools if parsing fails
        tool_names = ["get_critical_findings", "get_high_findings", "get_top_risks"]

    print(f"🔧 Agent selected tools: {tool_names}")

    # Step 2: Execute selected tools against Elasticsearch
    tool_results = {}
    for tool_name in tool_names:
        if tool_name in TOOL_REGISTRY:
            print(f"   ⚡ Calling: {tool_name}")
            result = TOOL_REGISTRY[tool_name]()
            tool_results[tool_name] = result

    # Step 3: Build context string from all tool results
    context = "ELASTICSEARCH DATA RETRIEVED:\n\n"
    for tool_name, result in tool_results.items():
        context += f"=== {tool_name.upper()} ===\n{result}\n\n"

    # Step 4: Final synthesis — Nova reasons over all gathered data
    final_prompt = f"""
    User question: "{user_query}"

    {context}

    Based on this real data from our cloud environment, provide a comprehensive,
    actionable answer. Be specific about resource IDs and findings.
    """

    final_response = call_nova([{"role": "user", "content": [{"text": final_prompt}]}])

    print("✅ Agent response ready!")

    return {
        "query": user_query,
        "tools_used": tool_names,
        "response": final_response,
        "data_sources": list(tool_results.keys())
    }