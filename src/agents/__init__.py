"""Agentic SOC (V0.4/5): read-only investigation agents.

The agent core lives in investigator.py. The API layer (src/api/agents.py)
and the MCP server (V0.4/5 item 2) both wrap it; neither grants the agent
any write capability. See the module docstring for the trust boundary.
"""
