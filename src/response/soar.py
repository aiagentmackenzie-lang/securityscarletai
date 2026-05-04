"""
SOAR Lite - Simple automated response actions.

Basic response playbooks for common scenarios.
Note: Automated blocking requires human approval at this stage.
"""
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from src.config.logging import get_logger

log = get_logger("response.soar")


class ActionType(Enum):
    """Supported response action types."""
    BLOCK_IP = "block_ip"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    KILL_PROCESS = "kill_process"
    NOTIFY = "notify"


@dataclass
class ResponseAction:
    """A single response action."""
    action_type: ActionType
    target: str
    reason: str
    approved: bool = False
    executed: bool = False
    result: Optional[str] = None


class SOARPlaybook:
    """Base class for response playbooks."""

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.actions: List[ResponseAction] = []

    def add_action(self, action: ResponseAction):
        """Add an action to the playbook."""
        self.actions.append(action)

    async def execute(self, dry_run: bool = True) -> List[ResponseAction]:
        """
        Execute the playbook.

        Args:
            dry_run: If True, only log what would be done without executing

        Returns:
            List of actions with results
        """
        results = []

        for action in self.actions:
            if not action.approved:
                action.result = "PENDING_APPROVAL"
                results.append(action)
                continue

            if dry_run:
                action.result = f"DRY_RUN: Would {action.action_type.value} {action.target}"
                log.info("soar_dry_run", action=action.action_type.value, target=action.target)
            else:
                action.result = await self._execute_action(action)
                action.executed = True

            results.append(action)

        return results

    async def _execute_action(self, action: ResponseAction) -> str:
        """Execute a single action. Override in subclasses."""
        if action.action_type == ActionType.BLOCK_IP:
            return await self._block_ip(action.target)
        elif action.action_type == ActionType.NOTIFY:
            return await self._send_notification(action.target, action.reason)
        else:
            return f"Action {action.action_type.value} not implemented"

    async def _block_ip(self, ip: str) -> str:
        """Block an IP using macOS pf firewall."""
        try:
            # Add rule to pf (requires sudo)
            rule = f'block drop quick from {ip} to any'
            log.warning("soar_ip_block", ip=ip, note="Requires manual sudo execution")
            return f"IP {ip} block rule prepared. Run: echo '{rule}' | sudo pfctl -f -"
        except Exception as e:
            log.error("soar_block_failed", ip=ip, error=str(e))
            return f"Failed: {str(e)}"

    async def _send_notification(self, message: str, reason: str) -> str:
        """Send notification via configured channels."""
        from src.response.notifications import send_slack_notification

        try:
            await send_slack_notification(f"{reason}: {message}")
            return "Notification sent"
        except Exception as e:
            return f"Notification failed: {str(e)}"


class BruteForcePlaybook(SOARPlaybook):
    """Response playbook for brute force attacks."""

    def __init__(self, attacker_ip: str, target_user: str):
        super().__init__(
            name="brute_force_response",
            description="Respond to brute force authentication attacks"
        )

        # Add actions (all pending approval)
        self.add_action(ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target=attacker_ip,
            reason=f"Brute force attack detected against user {target_user}",
            approved=False,
        ))

        self.add_action(ResponseAction(
            action_type=ActionType.NOTIFY,
            target=f"Security team: Brute force from {attacker_ip}",
            reason="Brute force attack detected",
            approved=True,  # Notifications auto-approved
        ))


class MalwarePlaybook(SOARPlaybook):
    """Response playbook for malware detection."""

    def __init__(self, host_name: str, process_name: str, user_name: str):
        super().__init__(
            name="malware_response",
            description="Respond to malware detection"
        )

        self.add_action(ResponseAction(
            action_type=ActionType.ISOLATE_HOST,
            target=host_name,
            reason=f"Malware detected: {process_name} on {host_name}",
            approved=False,
        ))

        self.add_action(ResponseAction(
            action_type=ActionType.DISABLE_USER,
            target=user_name,
            reason=f"User {user_name} executed malware",
            approved=False,
        ))

        self.add_action(ResponseAction(
            action_type=ActionType.NOTIFY,
            target=f"CRITICAL: Malware on {host_name}",
            reason="Malware detected",
            approved=True,
        ))


def get_playbook_for_alert(alert: dict) -> Optional[SOARPlaybook]:
    """
    Get appropriate playbook for an alert.

    Args:
        alert: Alert dictionary with rule_name, host_name, etc.

    Returns:
        Playbook instance or None
    """
    rule_name = alert.get("rule_name", "").lower()

    if "brute" in rule_name or "ssh" in rule_name:
        # Extract attacker IP from evidence if available
        return BruteForcePlaybook(
            attacker_ip="unknown",  # Would extract from alert
            target_user="admin",
        )

    if "malware" in rule_name or "suspicious" in rule_name:
        return MalwarePlaybook(
            host_name=alert.get("host_name", "unknown"),
            process_name="unknown",
            user_name="unknown",
        )

    return None
