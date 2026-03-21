"""
Configuration validation script.

Verifies environment setup before starting SecurityScarletAI.
Checks database, Ollama, osquery, and required directories.
"""
import asyncio
import sys
from pathlib import Path

import httpx
import asyncpg

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.config.settings import settings
from src.config.logging import get_logger

log = get_logger("validate")


async def check_postgresql() -> bool:
    """Check PostgreSQL connection."""
    try:
        conn = await asyncpg.connect(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
        )
        version = await conn.fetchval("SELECT version()")
        await conn.close()
        log.info("✅ PostgreSQL connected", version=version[:20])
        return True
    except Exception as e:
        log.error("❌ PostgreSQL connection failed", error=str(e))
        return False


async def check_ollama() -> bool:
    """Check Ollama availability."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name") for m in models]
                log.info("✅ Ollama available", models=model_names[:3])
                return True
            else:
                log.warning("⚠️ Ollama returned non-200 status", status=resp.status_code)
                return False
    except Exception as e:
        log.warning("⚠️ Ollama not available (optional)", error=str(e))
        return False


def check_osquery() -> bool:
    """Check osquery installation."""
    osquery_paths = [
        "/opt/homebrew/bin/osqueryi",
        "/usr/local/bin/osqueryi",
        "/usr/bin/osqueryi",
    ]
    
    for path in osquery_paths:
        if Path(path).exists():
            log.info("✅ osquery found", path=path)
            return True
    
    log.warning("⚠️ osquery not found in standard locations")
    return False


def check_directories() -> bool:
    """Check required directories exist."""
    required_dirs = [
        Path.home() / ".scarletai_backups",
        Path("data"),
        Path("logs"),
    ]
    
    all_ok = True
    for d in required_dirs:
        d.mkdir(parents=True, exist_ok=True)
        if not d.exists():
            log.error("❌ Directory not accessible", path=str(d))
            all_ok = False
    
    if all_ok:
        log.info("✅ All required directories exist")
    
    return all_ok


def check_env_file() -> bool:
    """Check .env file exists and has required variables."""
    env_path = Path(".env")
    
    if not env_path.exists():
        log.error("❌ .env file not found. Copy from .env.example:")
        log.error("   cp .env.example .env")
        return False
    
    # Check required variables
    required = ["DB_PASSWORD", "API_SECRET_KEY", "API_BEARER_TOKEN"]
    env_content = env_path.read_text()
    
    missing = []
    for var in required:
        if f"{var}=" not in env_content or f"{var}=CHANGE_ME" in env_content:
            missing.append(var)
    
    if missing:
        log.error("❌ Missing or placeholder values in .env:", vars=missing)
        return False
    
    log.info("✅ .env file configured")
    return True


async def main():
    """Run all validation checks."""
    print("=" * 60)
    print("SecurityScarletAI Configuration Validation")
    print("=" * 60)
    
    results = []
    
    # Run checks
    results.append(("Environment File", check_env_file()))
    results.append(("Directories", check_directories()))
    results.append(("PostgreSQL", await check_postgresql()))
    results.append(("Ollama (optional)", await check_ollama()))
    results.append(("osquery (optional)", check_osquery()))
    
    # Summary
    print("\n" + "=" * 60)
    print("Validation Summary")
    print("=" * 60)
    
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status:10} {name}")
    
    all_critical_passed = all(r[1] for r in results if r[0] not in ["Ollama (optional)", "osquery (optional)"])
    
    if all_critical_passed:
        print("\n✅ All critical checks passed! Ready to start.")
        print("\nStart the API:")
        print("  poetry run uvicorn src.api.main:app --reload")
        print("\nStart the dashboard:")
        print("  poetry run streamlit run dashboard/main.py")
        return 0
    else:
        print("\n❌ Some critical checks failed. Please fix the issues above.")
        return 1


if __name__ == "__main__":
    exit(asyncio.run(main()))
