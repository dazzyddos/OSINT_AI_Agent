import os

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools.shodan_tools import shodan_domain_search, shodan_host_lookup


def create_shodan_agent():
    """
    Create an agent specialized in Shodan reconnaissance.

    This agent queries Shodan to find exposed services and potential
    vulnerabilities on target infrastructure.
    """

    llm = ChatOpenAI(
        model="deepseek-chat",
        temperature=0,
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )

    system_prompt = """You are a Shodan intelligence analyst.

Your mission is to gather information about exposed services and potential vulnerabilities.

Instructions:
1. Use shodan_domain_search to find all hosts associated with the target domain
2. For hosts with interesting services, use shodan_host_lookup to get detailed info
3. Focus your analysis on:
   - Exposed administrative interfaces (ports 22, 3389, 8443)
   - Database services (3306, 5432, 27017, 6379)
   - Outdated software with known CVEs
   - Unusual or high ports that might indicate backdoors
   - Cloud metadata endpoints or misconfigurations
4. Prioritize findings by security impact

Think like a penetration tester - what would be most valuable to exploit?"""

    return create_react_agent(
        model=llm,
        tools=[shodan_host_lookup, shodan_domain_search],
        prompt=system_prompt,
    )
