```
 osint_agent/
  ├── docker/
  │   └── Dockerfile.tools        # Container with Subfinder, WhatWeb, httpx
  ├── agents/
  │   ├── __init__.py
  │   ├── state.py                # Shared state definition
  │   ├── coordinator.py          # Main supervisor agent
  │   ├── recon_agent.py          # Subdomain enumeration
  │   ├── shodan_agent.py         # Shodan lookups
  │   └── fingerprint_agent.py    # Tech detection with WhatWeb
  ├── tools/
  │   ├── __init__.py
  │   ├── docker_runner.py        # Docker execution wrapper
  │   ├── subdomain_tools.py
  │   ├── shodan_tools.py
  │   └── fingerprint_tools.py
  ├── config.py
  ├── main.py
  ├── requirements.txt
  └── .env.example
```

To run:
# 1. Build the Docker image
docker build -t osint-tools:latest -f docker/Dockerfile.tools .

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Set up environment
cp .env.example .env
# Edit .env with your OPENAI_API_KEY and SHODAN_API_KEY

# 4. Run an investigation
python main.py example.com