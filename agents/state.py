from typing import Annotated, TypedDict

from langgraph.graph.message import add_messages


class OSINTState(TypedDict):
    """Shared state for the OSINT multi-agent system"""

    # Target information
    target: str  # Domain we're investigating

    # Conversation messages (for LLM reasoning)
    messages: Annotated[list, add_messages]

    # Findings from reconnaissance
    subdomains: list[str]  # Discovered subdomains
    live_hosts: list[dict]  # Hosts that responded to probing
    shodan_hosts: list[dict]  # Shodan search results
    shodan_details: list[dict]  # Detailed Shodan host lookups
    technologies: list[dict]  # Technology fingerprints

    # Workflow control
    current_phase: str  # Current investigation phase
    completed_phases: list[str]  # Phases we've finished
    errors: list[str]  # Any errors encountered

    # Final output
    report: str  # Generated report
