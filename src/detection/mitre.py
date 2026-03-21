"""
MITRE ATT&CK data loader.

Downloads and caches ATT&CK tactics and techniques from the official STIX data.
"""
import json
import httpx
from pathlib import Path
from typing import Optional

from src.config.logging import get_logger

log = get_logger("detection.mitre")

# MITRE ATT&CK STIX data URL
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
CACHE_FILE = Path.home() / ".scarletai_mitre_cache.json"


class MitreAttackData:
    """MITRE ATT&CK data lookup."""
    
    def __init__(self):
        self._tactics: dict[str, str] = {}  # TA0001 -> Initial Access
        self._techniques: dict[str, dict] = {}  # T1234 -> {...}
        self._loaded = False
    
    async def load(self) -> None:
        """Load ATT&CK data from cache or download."""
        if self._loaded:
            return
        
        # Try cache first
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE) as f:
                    data = json.load(f)
                    self._tactics = data.get("tactics", {})
                    self._techniques = data.get("techniques", {})
                    self._loaded = True
                    log.info("mitre_loaded_from_cache", tactics=len(self._tactics), techniques=len(self._techniques))
                    return
            except Exception:
                log.warning("mitre_cache_load_failed")
        
        # Download fresh data
        await self._download()
    
    async def _download(self) -> None:
        """Download ATT&CK STIX data."""
        log.info("downloading_mitre_data")
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(ATTACK_STIX_URL, timeout=60)
            resp.raise_for_status()
            stix_data = resp.json()
        
        # Parse STIX objects
        for obj in stix_data.get("objects", []):
            obj_type = obj.get("type")
            
            if obj_type == "x-mitre-tactic":
                # Tactic: TA0001
                external_refs = obj.get("external_references", [])
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tactic_id = ref.get("external_id")
                        if tactic_id:
                            self._tactics[tactic_id] = obj.get("name", "")
            
            elif obj_type == "attack-pattern":
                # Technique: T1234
                external_refs = obj.get("external_references", [])
                for ref in external_refs:
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        if tech_id and tech_id.startswith("T"):
                            self._techniques[tech_id] = {
                                "id": tech_id,
                                "name": obj.get("name", ""),
                                "description": obj.get("description", ""),
                                "kill_chain_phases": obj.get("kill_chain_phases", []),
                            }
        
        # Save cache
        with open(CACHE_FILE, "w") as f:
            json.dump({
                "tactics": self._tactics,
                "techniques": self._techniques,
            }, f)
        
        self._loaded = True
        log.info("mitre_downloaded", tactics=len(self._tactics), techniques=len(self._techniques))
    
    def get_tactic_name(self, tactic_id: str) -> Optional[str]:
        """Get tactic name from ID (e.g., TA0001 -> Initial Access)."""
        return self._tactics.get(tactic_id)
    
    def get_technique_name(self, technique_id: str) -> Optional[str]:
        """Get technique name from ID (e.g., T1234 -> name)."""
        tech = self._techniques.get(technique_id)
        return tech["name"] if tech else None
    
    def get_technique_info(self, technique_id: str) -> Optional[dict]:
        """Get full technique info."""
        return self._techniques.get(technique_id)
    
    def search_techniques(self, query: str) -> list[dict]:
        """Search techniques by name or ID."""
        query_lower = query.lower()
        results = []
        for tech_id, tech in self._techniques.items():
            if query_lower in tech_id.lower() or query_lower in tech.get("name", "").lower():
                results.append(tech)
        return results[:10]  # Limit results


# Global instance
_mitre_data: Optional[MitreAttackData] = None


async def get_mitre_data() -> MitreAttackData:
    """Get singleton MITRE ATT&CK data instance."""
    global _mitre_data
    if _mitre_data is None:
        _mitre_data = MitreAttackData()
        await _mitre_data.load()
    return _mitre_data
