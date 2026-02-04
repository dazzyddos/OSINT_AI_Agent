# OSINT Multi-Agent System

A multi-agent OSINT (Open Source Intelligence) reconnaissance framework built with [LangGraph](https://github.com/langchain-ai/langgraph). This project demonstrates how to orchestrate specialized AI agents that collaborate to perform comprehensive security reconnaissance on target domains.

Note: This is a simple tool built for learning purposes to demonstrate how to get started with building AI Agents in the cybersecurity field. For a detailed walkthrough and explanation, check out the accompanying blog post: Building AI Agents for Cybersecurity with LangGraph. 

## Overview

This system uses a supervisor architecture where a coordinator agent orchestrates three specialized agents through a reconnaissance workflow:

```
┌─────────────────────────────────────────────────────────────────┐
│                        COORDINATOR                              │
│                    (Supervisor Agent)                           │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
     ┌──────────┐    ┌──────────┐    ┌──────────────┐
     │  RECON   │    │  SHODAN  │    │ FINGERPRINT  │
     │  AGENT   │    │  AGENT   │    │    AGENT     │
     └────┬─────┘    └────┬─────┘    └──────┬───────┘
          │               │                 │
          ▼               ▼                 ▼
     ┌──────────┐    ┌──────────┐    ┌──────────────┐
     │Subfinder │    │ Shodan   │    │   WhatWeb    │
     │ (Docker) │    │   API    │    │   (Docker)   │
     └──────────┘    └──────────┘    └──────────────┘
```

**Workflow Phases:**
1. **Reconnaissance** → Subdomain enumeration using Subfinder
2. **Shodan Intelligence** → Query exposed services and vulnerabilities  
3. **Fingerprinting** → Technology stack identification with WhatWeb
4. **Reporting** → AI-generated security assessment report

## Features

- **Multi-Agent Architecture**: Specialized agents with distinct responsibilities
- **Docker Isolation**: Security tools run in containers for safety and reproducibility
- **State Management**: LangGraph handles conversation flow and data persistence
- **Checkpointing**: Optional resume capability for long-running investigations
- **Structured Output**: Pydantic models ensure consistent data formats
- **Comprehensive Reports**: LLM-generated penetration testing reports

## Project Structure

```
osint_agent/
├── agents/
│   ├── __init__.py
│   ├── state.py                # Shared state definition (TypedDict)
│   ├── coordinator.py          # Supervisor agent & graph definition
│   ├── recon_agent.py          # Subdomain enumeration agent
│   ├── shodan_agent.py         # Shodan reconnaissance agent
│   └── fingerprint_agent.py    # Technology detection agent
├── tools/
│   ├── __init__.py
│   ├── docker_runner.py        # Docker execution wrapper
│   ├── subdomain_tools.py      # Subfinder integration
│   ├── shodan_tools.py         # Shodan API tools
│   └── fingerprint_tools.py    # WhatWeb integration
├── docker/
│   └── Dockerfile.tools        # Container with recon tools
├── config.py                   # Application configuration
├── main.py                     # CLI entry point
├── requirements.txt
└── .env.example
```

## Prerequisites

- Python 3.11+
- Docker (for running security tools)
- [DeepSeek API Key](https://platform.deepseek.com/) (or modify for OpenAI/Anthropic)
- [Shodan API Key](https://account.shodan.io/)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/osint-agent.git
cd osint-agent
```

### 2. Build the Docker Image

The Docker image contains Subfinder, WhatWeb, and httpx for reconnaissance:

```bash
docker build -t osint-tools:latest -f docker/Dockerfile.tools .
```

### 3. Install Python Dependencies

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your API keys:

```env
DEEPSEEK_API_KEY=your-deepseek-api-key
SHODAN_API_KEY=your-shodan-api-key

# Optional configuration
OSINT_DOCKER_IMAGE=osint-tools:latest
DOCKER_TIMEOUT=300
LLM_MODEL=deepseek-chat
LLM_TEMPERATURE=0
```

## Usage

### Basic Investigation

```bash
python main.py example.com
```

### With Checkpointing (Resume Capability)

```bash
python main.py example.com --checkpoint
```

### Programmatic Usage

```python
from agents.coordinator import create_coordinator
from langgraph.checkpoint.memory import MemorySaver

# Create coordinator with optional checkpointing
checkpointer = MemorySaver()
coordinator = create_coordinator(checkpointer=checkpointer)

# Initialize state
initial_state = {
    "target": "example.com",
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

# Run investigation
config = {"configurable": {"thread_id": "osint-example"}}
for event in coordinator.stream(initial_state, config):
    print(event)
```

## Agent Details

### Coordinator (Supervisor)

The coordinator implements a state machine that routes execution through the workflow phases:

```python
def supervisor_node(state: OSINTState) -> Command:
    completed = state.get("completed_phases", [])
    
    if "recon" not in completed:
        return Command(goto="recon_node", update={"current_phase": "recon"})
    elif "shodan" not in completed:
        return Command(goto="shodan_node", update={"current_phase": "shodan"})
    # ... continues through phases
```

### Recon Agent

Specializes in subdomain enumeration using passive techniques:
- Certificate Transparency logs
- DNS datasets
- Web archives
- Public sources via Subfinder

### Shodan Agent

Queries Shodan for exposed infrastructure:
- Open ports and services
- Known vulnerabilities (CVEs)
- Operating system detection
- Service banners

### Fingerprint Agent

Identifies technology stacks using WhatWeb:
- Web servers (Apache, Nginx, IIS)
- CMS platforms (WordPress, Drupal)
- JavaScript frameworks
- Programming languages
- Security headers

## State Schema

The shared state uses LangGraph's TypedDict with message annotation:

```python
class OSINTState(TypedDict):
    target: str                           # Domain being investigated
    messages: Annotated[list, add_messages]  # LLM conversation history
    subdomains: list[str]                 # Discovered subdomains
    live_hosts: list[dict]                # Responsive hosts
    shodan_hosts: list[dict]              # Shodan search results
    shodan_details: list[dict]            # Detailed host lookups
    technologies: list[dict]              # Fingerprint results
    current_phase: str                    # Active workflow phase
    completed_phases: list[str]           # Finished phases
    errors: list[str]                     # Error collection
    report: str                           # Final report
```

## Graph Visualization

The LangGraph workflow:

```
                    ┌─────────┐
                    │  START  │
                    └────┬────┘
                         │
                         ▼
                 ┌────────────┐
          ┌──────│ SUPERVISOR │◄─────────────────┐
          │      └────────────┘                  │
          │            │                         │
          │  ┌─────────┼─────────┐               │
          │  │         │         │               │
          ▼  ▼         ▼         ▼               │
     ┌────────┐  ┌─────────┐  ┌─────────────┐    │
     │ RECON  │  │ SHODAN  │  │ FINGERPRINT │    │
     │  NODE  │  │  NODE   │  │    NODE     │    │
     └───┬────┘  └────┬────┘  └──────┬──────┘    │
         │            │              │           │
         └────────────┴──────────────┴───────────┘
                         │
                         ▼ (all phases complete)
                  ┌────────────┐
                  │   REPORT   │
                  │    NODE    │
                  └─────┬──────┘
                        │
                        ▼
                    ┌───────┐
                    │  END  │
                    └───────┘
```

## Sample Output

```
+==============================================================+
|           OSINT Multi-Agent Investigation                    |
+==============================================================+
|  Target: example.com                                         |
+==============================================================+

[*] Starting investigation...

[->] Moving to phase: recon
[OK] Recon complete: found 47 subdomains
[->] Moving to phase: shodan
[OK] Shodan complete: found 12 hosts
[->] Moving to phase: fingerprint
[OK] Fingerprinting complete: scanned 10 targets
[->] Moving to phase: reporting
[OK] Report generated

============================================================
INVESTIGATION COMPLETE
============================================================

# OSINT Reconnaissance Report: example.com

## Executive Summary
...
```

## Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `DEEPSEEK_API_KEY` | Required | API key for DeepSeek LLM |
| `SHODAN_API_KEY` | Required | API key for Shodan queries |
| `OSINT_DOCKER_IMAGE` | `osint-tools:latest` | Docker image for tools |
| `DOCKER_TIMEOUT` | `300` | Max execution time (seconds) |
| `LLM_MODEL` | `deepseek-chat` | LLM model identifier |
| `LLM_TEMPERATURE` | `0` | LLM temperature setting |

## Extending the System

### Adding a New Agent

1. Create the agent in `agents/`:

```python
# agents/new_agent.py
from langgraph.prebuilt import create_react_agent

def create_new_agent():
    llm = ChatOpenAI(...)
    return create_react_agent(
        model=llm,
        tools=[your_tools],
        prompt="Your system prompt"
    )
```

2. Add tools in `tools/`:

```python
# tools/new_tools.py
from langchain_core.tools import tool

@tool
def your_new_tool(param: str) -> dict:
    """Tool description for the LLM."""
    # Implementation
    return result
```

3. Register in the coordinator graph:

```python
# In coordinator.py
builder.add_node("new_node", new_node_function)
builder.add_edge("new_node", "supervisor")
```

### Using Different LLMs

Modify the LLM initialization in agent files:

```python
# For OpenAI
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4o")

# For Anthropic
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-sonnet-4-20250514")
```

## Security Considerations

- **Docker Isolation**: All reconnaissance tools run in containers with resource limits
- **Input Sanitization**: Domain inputs are escaped using `shlex.quote()`
- **API Key Management**: Credentials loaded from environment variables
- **Rate Limiting**: Shodan queries limited to 25 results per search
- **Timeouts**: Configurable execution timeouts prevent runaway processes

## Limitations

- Passive reconnaissance only (no active scanning)
- Requires Docker for tool execution
- Shodan API has rate limits on free tier
- WhatWeb fingerprinting limited to HTTP/HTTPS

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [LangGraph](https://github.com/langchain-ai/langgraph) - Multi-agent orchestration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain enumeration
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Technology fingerprinting
- [Shodan](https://www.shodan.io/) - Internet intelligence
- [DeepSeek](https://www.deepseek.com/) - LLM provider

---

**Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Always obtain proper authorization before conducting reconnaissance on any target.