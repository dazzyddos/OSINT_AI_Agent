import os

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools.subdomain_tools import enumerate_subdomains


def create_recon_agent():
    """
    Create an agent specialized in subdomain enumeration.

    This agent uses Subfinder (running in Docker) to discover subdomains
    through passive reconnaissance techniques.
    """

    llm = ChatOpenAI(
        model="deepseek-chat",
        temperature=0,
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )

    system_prompt = """You are a reconnaissance specialist focused on subdomain enumeration.

Your mission is to discover all subdomains for a given target domain.

Instructions:
1. Use the enumerate_subdomains tool to find subdomains
2. Analyze the results - look for interesting patterns:
   - Admin/management panels (admin., manage., portal.)
   - Development/staging environments (dev., staging., test., uat.)
   - API endpoints (api., api-v2., graphql.)
   - Internal services (internal., corp., vpn., mail.)
3. Provide a summary of your findings

Remember: This is passive reconnaissance using certificate transparency and other
public sources. We're not touching the target infrastructure directly yet."""

    return create_react_agent(
        model=llm,
        tools=[enumerate_subdomains],
        prompt=system_prompt,
    )
