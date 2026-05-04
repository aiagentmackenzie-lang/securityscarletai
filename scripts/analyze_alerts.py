#!/usr/bin/env python3
"""Manually run AI analysis on alerts that don't have ai_summary yet."""
import asyncio
import sys
import os

# Security: Use relative import path instead of hardcoded absolute path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.db.connection import get_pool
from src.detection.ai_analyzer import analyze_alert, enrich_alert


async def main():
    pool = await get_pool()
    async with pool.acquire() as conn:
        alerts = await conn.fetch(
            "SELECT id, rule_name, severity, host_name, evidence FROM alerts WHERE ai_summary IS NULL OR ai_summary = '' ORDER BY id"
        )
    
    print(f"Found {len(alerts)} alerts without AI analysis")
    
    for alert in alerts:
        alert_id = alert["id"]
        print(f"\n🔍 Analyzing alert #{alert_id}: {alert['rule_name']}...")
        
        # Parse evidence
        import json
        try:
            evidence = json.loads(alert["evidence"]) if alert["evidence"] else {}
        except:
            evidence = {}
        
        analysis = await analyze_alert(
            alert_id=alert_id,
            rule_name=alert["rule_name"],
            severity=alert["severity"],
            host_name=alert["host_name"],
            evidence=evidence,
        )
        
        if analysis:
            await enrich_alert(alert_id, analysis)
            print(f"  ✅ Risk: {analysis.get('risk_score', '?')}/100 — {analysis.get('summary', '')[:80]}")
        else:
            print(f"  ❌ Analysis failed")
    
    print("\nDone!")


if __name__ == "__main__":
    asyncio.run(main())