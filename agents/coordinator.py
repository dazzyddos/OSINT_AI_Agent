import json
import logging
import os
from typing import Any

from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from agents.fingerprint_agent import create_fingerprint_agent
from agents.recon_agent import create_recon_agent
from agents.shodan_agent import create_shodan_agent
from agents.state import OSINTState

logger = logging.getLogger(__name__)


def _extract_json_from_content(content: Any) -> dict | None:
    """Safely extract JSON from message content"""
    if isinstance(content, dict):
        return content
    if isinstance(content, str):
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None
    return None


def create_coordinator(checkpointer=None):
    """
    Create the multi-agent OSINT coordinator.

    This supervisor orchestrates specialized agents through the reconnaissance
    workflow: subdomain enumeration -> Shodan lookup -> technology fingerprinting -> reporting
    """

    # Initialize specialized agents
    recon_agent = create_recon_agent()
    shodan_agent = create_shodan_agent()
    fingerprint_agent = create_fingerprint_agent()

    # LLM for report generation
    report_llm = ChatOpenAI(
        model="deepseek-chat",
        temperature=0.3,
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )

    # ==================== NODES ====================

    def supervisor_node(state: OSINTState) -> Command:
        """Route to the next phase based on current progress"""
        completed = state.get("completed_phases", [])

        logger.info(f"Supervisor: completed phases = {completed}")

        if "recon" not in completed:
            return Command(goto="recon_node", update={"current_phase": "recon"})
        elif "shodan" not in completed:
            return Command(goto="shodan_node", update={"current_phase": "shodan"})
        elif "fingerprint" not in completed:
            # Only fingerprint if we found subdomains
            if len(state.get("subdomains", [])) > 0:
                return Command(
                    goto="fingerprint_node", update={"current_phase": "fingerprint"}
                )
            else:
                return Command(
                    goto="report_node",
                    update={
                        "current_phase": "reporting",
                        "completed_phases": completed + ["fingerprint"],
                    },
                )
        else:
            return Command(goto="report_node", update={"current_phase": "reporting"})

    def recon_node(state: OSINTState) -> dict:
        """Execute subdomain enumeration"""
        logger.info(f"Starting reconnaissance for: {state['target']}")

        try:
            result = recon_agent.invoke(
                {"messages": [("user", f"Find all subdomains for: {state['target']}")]}
            )

            # Extract subdomains from tool results in messages
            subdomains = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name") and msg.name == "enumerate_subdomains":
                    content = _extract_json_from_content(msg.content)
                    if content:
                        subdomains.extend(content.get("subdomains", []))

            # Deduplicate
            subdomains = list(set(subdomains))

            return {
                "messages": result["messages"],
                "subdomains": subdomains,
                "completed_phases": state.get("completed_phases", []) + ["recon"],
            }

        except Exception as e:
            logger.error(f"Recon failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Recon error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["recon"],
            }

    def shodan_node(state: OSINTState) -> dict:
        """Execute Shodan reconnaissance"""
        logger.info(f"Starting Shodan lookup for: {state['target']}")

        try:
            subdomains_sample = state.get("subdomains", [])[:20]
            result = shodan_agent.invoke(
                {
                    "messages": [
                        (
                            "user",
                            f"Search Shodan for hosts related to: {state['target']}. "
                            f"We found these subdomains: {subdomains_sample}",
                        )
                    ]
                }
            )

            # Parse Shodan results from messages
            shodan_hosts = []
            shodan_details = []

            for msg in result.get("messages", []):
                if hasattr(msg, "name"):
                    content = _extract_json_from_content(msg.content)
                    if content:
                        if msg.name == "shodan_domain_search":
                            shodan_hosts.extend(content.get("hosts", []))
                        elif msg.name == "shodan_host_lookup":
                            shodan_details.append(content)

            return {
                "messages": result["messages"],
                "shodan_hosts": shodan_hosts,
                "shodan_details": shodan_details,
                "completed_phases": state.get("completed_phases", []) + ["shodan"],
            }

        except Exception as e:
            logger.error(f"Shodan lookup failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Shodan error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["shodan"],
            }

    def fingerprint_node(state: OSINTState) -> dict:
        """Execute technology fingerprinting"""
        subdomains = state.get("subdomains", [])[:10]  # Limit for performance

        if not subdomains:
            logger.info("No subdomains to fingerprint, skipping")
            return {
                "completed_phases": state.get("completed_phases", []) + ["fingerprint"]
            }

        logger.info(f"Fingerprinting {len(subdomains)} targets")

        # Build URLs from subdomains
        urls = [f"https://{sub}" for sub in subdomains]

        try:
            result = fingerprint_agent.invoke(
                {
                    "messages": [
                        (
                            "user",
                            f"Fingerprint these URLs to identify their technology stack: {urls}",
                        )
                    ]
                }
            )

            # Parse fingerprint results
            technologies = []
            for msg in result.get("messages", []):
                if hasattr(msg, "name") and "fingerprint" in msg.name:
                    content = _extract_json_from_content(msg.content)
                    if content:
                        if "results" in content:
                            technologies.extend(content["results"])
                        elif "technologies" in content:
                            technologies.append(content)

            return {
                "messages": result["messages"],
                "technologies": technologies,
                "completed_phases": state.get("completed_phases", []) + ["fingerprint"],
            }

        except Exception as e:
            logger.error(f"Fingerprinting failed: {e}")
            return {
                "errors": state.get("errors", []) + [f"Fingerprint error: {str(e)}"],
                "completed_phases": state.get("completed_phases", []) + ["fingerprint"],
            }

    def report_node(state: OSINTState) -> dict:
        """Generate the final reconnaissance report"""
        logger.info("Generating final report")

        # Compile all findings
        findings_summary = {
            "target": state["target"],
            "subdomains_count": len(state.get("subdomains", [])),
            "subdomains_sample": state.get("subdomains", [])[:20],
            "shodan_hosts": len(state.get("shodan_hosts", [])),
            "shodan_details": state.get("shodan_details", []),
            "technologies": state.get("technologies", []),
            "errors": state.get("errors", []),
        }

        report_prompt = f"""Generate a professional OSINT reconnaissance report based on these findings:

{json.dumps(findings_summary, indent=2, default=str)}

Structure the report as follows:

# OSINT Reconnaissance Report: {state['target']}

## Executive Summary
Brief overview of findings and overall security posture.

## Discovered Assets
- Total subdomains found
- Notable subdomains (admin panels, APIs, dev environments)
- IP addresses and hosting information

## Exposed Services (from Shodan)
- Open ports and services
- Potential vulnerabilities (CVEs)
- Outdated software

## Technology Stack
- Web servers
- Frameworks and CMS platforms
- Notable version information

## Risk Assessment
Prioritized list of findings by security impact.

## Recommendations
Actionable next steps for further investigation or remediation.

Be specific, technical, and actionable. This is for a security professional."""

        response = report_llm.invoke(
            [
                (
                    "system",
                    "You are a senior penetration tester writing a reconnaissance report.",
                ),
                ("user", report_prompt),
            ]
        )

        return {"report": response.content}

    # ==================== BUILD GRAPH ====================

    builder = StateGraph(OSINTState)

    # Add nodes
    builder.add_node("supervisor", supervisor_node)
    builder.add_node("recon_node", recon_node)
    builder.add_node("shodan_node", shodan_node)
    builder.add_node("fingerprint_node", fingerprint_node)
    builder.add_node("report_node", report_node)

    # Define edges
    builder.add_edge(START, "supervisor")
    builder.add_edge("recon_node", "supervisor")
    builder.add_edge("shodan_node", "supervisor")
    builder.add_edge("fingerprint_node", "supervisor")
    builder.add_edge("report_node", END)

    # Compile with optional checkpointer
    if checkpointer:
        return builder.compile(checkpointer=checkpointer)
    return builder.compile()
