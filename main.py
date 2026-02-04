import logging
import os
import sys

from dotenv import load_dotenv
from langgraph.checkpoint.memory import MemorySaver

from agents.coordinator import create_coordinator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

load_dotenv()


def run_osint_investigation(target: str, use_checkpointing: bool = False) -> str:
    """
    Run a complete OSINT investigation on a target domain.

    Args:
        target: Domain to investigate (e.g., "example.com")
        use_checkpointing: Enable state persistence for resume capability

    Returns:
        The generated reconnaissance report
    """

    # Validate environment
    if not os.getenv("DEEPSEEK_API_KEY"):
        raise ValueError("DEEPSEEK_API_KEY environment variable not set")

    if not os.getenv("SHODAN_API_KEY"):
        logger.warning("SHODAN_API_KEY not set - Shodan lookups will fail")

    # Create coordinator with optional checkpointing
    checkpointer = MemorySaver() if use_checkpointing else None
    coordinator = create_coordinator(checkpointer=checkpointer)

    # Initialize state
    initial_state = {
        "target": target,
        "messages": [],
        "subdomains": [],
        "live_hosts": [],
        "shodan_hosts": [],
        "shodan_details": [],
        "technologies": [],
        "current_phase": "",
        "completed_phases": [],
        "errors": [],
        "report": "",
    }

    # Config for checkpointing
    config = (
        {"configurable": {"thread_id": f"osint-{target}"}} if use_checkpointing else {}
    )

    print(
        f"""
+==============================================================+
|           OSINT Multi-Agent Investigation                    |
+==============================================================+
|  Target: {target:<50}|
+==============================================================+
    """
    )

    # Stream execution to show progress
    print("[*] Starting investigation...\n")

    final_state = None
    for event in coordinator.stream(initial_state, config):
        for node_name, node_output in event.items():
            if node_name == "__end__":
                continue

            # Progress indicators
            if node_name == "supervisor":
                phase = node_output.get("current_phase", "")
                if phase:
                    print(f"[->] Moving to phase: {phase}")
            elif node_name == "recon_node":
                subs = node_output.get("subdomains", [])
                print(f"[OK] Recon complete: found {len(subs)} subdomains")
            elif node_name == "shodan_node":
                hosts = node_output.get("shodan_hosts", [])
                print(f"[OK] Shodan complete: found {len(hosts)} hosts")
            elif node_name == "fingerprint_node":
                techs = node_output.get("technologies", [])
                print(f"[OK] Fingerprinting complete: scanned {len(techs)} targets")
            elif node_name == "report_node":
                print("[OK] Report generated")

            final_state = node_output

    # Get the final report
    if final_state and "report" in final_state:
        report = final_state["report"]
    else:
        # Invoke one more time to get complete state
        final_state = coordinator.invoke(initial_state, config)
        report = final_state.get("report", "No report generated")

    print("\n" + "=" * 60)
    print("INVESTIGATION COMPLETE")
    print("=" * 60 + "\n")

    return report


def main():
    if len(sys.argv) < 2:
        print(
            """
Usage: python main.py <target_domain> [--checkpoint]

Arguments:
    target_domain    Domain to investigate (e.g., example.com)
    --checkpoint     Enable state persistence for resume capability

Examples:
    python main.py example.com
    python main.py example.com --checkpoint
        """
        )
        sys.exit(1)

    target = sys.argv[1]
    use_checkpointing = "--checkpoint" in sys.argv

    try:
        report = run_osint_investigation(target, use_checkpointing)
        print(report)

        # Optionally save report to file
        report_file = f"report_{target.replace('.', '_')}.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\n[*] Report saved to: {report_file}")

    except KeyboardInterrupt:
        print("\n[!] Investigation interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.exception("Investigation failed")
        print(f"\n[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
