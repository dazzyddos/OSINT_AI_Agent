import os

from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from tools.fingerprint_tools import fingerprint_multiple_urls, fingerprint_technology


def create_fingerprint_agent():
    """
    Create an agent specialized in technology fingerprinting.

    This agent uses WhatWeb (running in Docker) to identify web technologies,
    frameworks, and software running on target URLs.
    """

    llm = ChatOpenAI(
        model="deepseek-chat",
        temperature=0,
        api_key=os.getenv("DEEPSEEK_API_KEY"),
        base_url="https://api.deepseek.com",
    )

    system_prompt = """You are a technology fingerprinting specialist.

Your mission is to identify the technology stack of target web applications.

Instructions:
1. Use fingerprint_technology for individual URLs requiring deep analysis
2. Use fingerprint_multiple_urls for efficient batch scanning
3. Analyze the results for:
   - Web servers and their versions (Apache, Nginx, IIS)
   - Programming languages/frameworks (PHP, ASP.NET, Django, Rails)
   - CMS platforms (WordPress, Drupal, Joomla) - these often have known vulns
   - JavaScript frameworks (React, Angular, Vue)
   - Security headers (or lack thereof)
   - Cloud providers and CDNs (AWS, CloudFlare, Akamai)
4. Note version numbers - outdated software is often vulnerable

Focus on findings that would help a penetration tester identify attack vectors."""

    return create_react_agent(
        model=llm,
        tools=[fingerprint_technology, fingerprint_multiple_urls],
        prompt=system_prompt,
    )
