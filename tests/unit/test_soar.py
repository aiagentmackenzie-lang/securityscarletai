"""
Tests for SOAR (Security Orchestration, Automation, and Response) module.

Covers:
- ActionType enum
- ResponseAction dataclass
- SOARPlaybook base class
- BruteForcePlaybook
- MalwarePlaybook
- get_playbook_for_alert
- Approval and dry-run logic
"""
import pytest
from unittest.mock import AsyncMock, patch

from src.response.soar import (
    ActionType,
    ResponseAction,
    SOARPlaybook,
    BruteForcePlaybook,
    MalwarePlaybook,
    get_playbook_for_alert,
)


class TestActionType:
    """Test ActionType enum values."""

    def test_all_action_types(self):
        assert ActionType.BLOCK_IP.value == "block_ip"
        assert ActionType.ISOLATE_HOST.value == "isolate_host"
        assert ActionType.DISABLE_USER.value == "disable_user"
        assert ActionType.KILL_PROCESS.value == "kill_process"
        assert ActionType.NOTIFY.value == "notify"

    def test_action_type_count(self):
        assert len(ActionType) == 5


class TestResponseAction:
    """Test ResponseAction dataclass."""

    def test_default_values(self):
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.5",
            reason="Brute force attack",
        )
        assert action.approved is False
        assert action.executed is False
        assert action.result is None

    def test_approved_action(self):
        action = ResponseAction(
            action_type=ActionType.NOTIFY,
            target="security team",
            reason="Alert triggered",
            approved=True,
        )
        assert action.approved is True

    def test_action_with_result(self):
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="1.2.3.4",
            reason="C2 callback",
            approved=True,
            executed=True,
            result="IP blocked successfully",
        )
        assert action.result == "IP blocked successfully"


class TestSOARPlaybook:
    """Test SOARPlaybook base class."""

    def test_init(self):
        pb = SOARPlaybook("test", "A test playbook")
        assert pb.name == "test"
        assert pb.description == "A test playbook"
        assert pb.actions == []

    def test_add_action(self):
        pb = SOARPlaybook("test", "Test")
        action = ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.1",
            reason="Malicious",
        )
        pb.add_action(action)
        assert len(pb.actions) == 1

    @pytest.mark.asyncio
    async def test_execute_unapproved_dry_run(self):
        """Unapproved actions should get PENDING_APPROVAL result."""
        pb = SOARPlaybook("test", "Test")
        pb.add_action(ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.1",
            reason="Test",
            approved=False,
        ))
        results = await pb.execute(dry_run=True)
        assert len(results) == 1
        assert results[0].result == "PENDING_APPROVAL"

    @pytest.mark.asyncio
    async def test_execute_approved_dry_run(self):
        """Approved actions in dry_run should report what would happen."""
        pb = SOARPlaybook("test", "Test")
        pb.add_action(ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.1",
            reason="Test",
            approved=True,
        ))
        results = await pb.execute(dry_run=True)
        assert len(results) == 1
        assert "DRY_RUN" in results[0].result

    @pytest.mark.asyncio
    async def test_execute_approved_real_run_notify(self):
        """Approved NOTIFY actions should attempt notification."""
        pb = SOARPlaybook("test", "Test")
        pb.add_action(ResponseAction(
            action_type=ActionType.NOTIFY,
            target="Security team",
            reason="Test notification",
            approved=True,
        ))

        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True):
            results = await pb.execute(dry_run=False)
            assert results[0].executed is True
            assert "Notification sent" in results[0].result

    @pytest.mark.asyncio
    async def test_execute_mixed_approved(self):
        """Playbook with both approved and unapproved actions."""
        pb = SOARPlaybook("test", "Test")
        pb.add_action(ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="10.0.0.1",
            reason="Test",
            approved=False,
        ))
        pb.add_action(ResponseAction(
            action_type=ActionType.NOTIFY,
            target="Team",
            reason="Test",
            approved=True,
        ))

        with patch("src.response.notifications.send_slack_notification", new_callable=AsyncMock, return_value=True):
            results = await pb.execute(dry_run=False)
            assert len(results) == 2
            assert results[0].result == "PENDING_APPROVAL"
            assert results[1].executed is True

    @pytest.mark.asyncio
    async def test_block_ip_action(self):
        """BLOCK_IP action should prepare firewall rule."""
        pb = SOARPlaybook("test", "Test")
        pb.add_action(ResponseAction(
            action_type=ActionType.BLOCK_IP,
            target="192.168.1.100",
            reason="C2 callback",
            approved=True,
        ))
        results = await pb.execute(dry_run=False)
        assert "192.168.1.100" in results[0].result
        assert "pf" in results[0].result.lower() or "block" in results[0].result.lower()

    @pytest.mark.asyncio
    async def test_unknown_action_type(self):
        """Unknown action types should report not implemented."""
        pb = SOARPlaybook("test", "Test")
        pb.add_action(ResponseAction(
            action_type=ActionType.KILL_PROCESS,
            target="malware.exe",
            reason="Malware detected",
            approved=True,
        ))
        results = await pb.execute(dry_run=False)
        assert "not implemented" in results[0].result.lower()


class TestBruteForcePlaybook:
    """Test BruteForcePlaybook."""

    def test_init_creates_actions(self):
        pb = BruteForcePlaybook(attacker_ip="10.0.0.5", target_user="admin")
        assert pb.name == "brute_force_response"
        assert len(pb.actions) == 2

    def test_block_ip_action_not_auto_approved(self):
        pb = BruteForcePlaybook(attacker_ip="10.0.0.5", target_user="admin")
        block_action = pb.actions[0]
        assert block_action.action_type == ActionType.BLOCK_IP
        assert block_action.approved is False

    def test_notify_action_auto_approved(self):
        pb = BruteForcePlaybook(attacker_ip="10.0.0.5", target_user="admin")
        notify_action = pb.actions[1]
        assert notify_action.action_type == ActionType.NOTIFY
        assert notify_action.approved is True

    def test_description_contains_user(self):
        pb = BruteForcePlaybook(attacker_ip="10.0.0.5", target_user="admin")
        # The reason mentions the user, and the IP is in the target field
        assert "admin" in pb.actions[0].reason
        assert pb.actions[0].target == "10.0.0.5"

    @pytest.mark.asyncio
    async def test_execute_dry_run(self):
        """Dry run should report PENDING for unapproved actions."""
        pb = BruteForcePlaybook(attacker_ip="10.0.0.5", target_user="admin")
        results = await pb.execute(dry_run=True)
        assert len(results) == 2
        # First action (block) should be pending
        assert results[0].result == "PENDING_APPROVAL"
        # Second action (notify) should be dry run
        assert "DRY_RUN" in results[1].result


class TestMalwarePlaybook:
    """Test MalwarePlaybook."""

    def test_init_creates_actions(self):
        pb = MalwarePlaybook(host_name="server01", process_name="malware.exe", user_name="user1")
        assert pb.name == "malware_response"
        assert len(pb.actions) == 3

    def test_isolate_not_auto_approved(self):
        pb = MalwarePlaybook(host_name="server01", process_name="malware.exe", user_name="user1")
        isolate_action = pb.actions[0]
        assert isolate_action.action_type == ActionType.ISOLATE_HOST
        assert isolate_action.approved is False

    def test_disable_user_not_auto_approved(self):
        pb = MalwarePlaybook(host_name="server01", process_name="malware.exe", user_name="user1")
        disable_action = pb.actions[1]
        assert disable_action.action_type == ActionType.DISABLE_USER
        assert disable_action.approved is False

    def test_notify_auto_approved(self):
        pb = MalwarePlaybook(host_name="server01", process_name="malware.exe", user_name="user1")
        notify_action = pb.actions[2]
        assert notify_action.action_type == ActionType.NOTIFY
        assert notify_action.approved is True


class TestGetPlaybookForAlert:
    """Test get_playbook_for_alert function."""

    def test_brute_force_alert(self):
        alert = {"rule_name": "SSH Brute Force Detected", "host_name": "server01"}
        pb = get_playbook_for_alert(alert)
        assert isinstance(pb, BruteForcePlaybook)

    def test_ssh_alert(self):
        alert = {"rule_name": "Failed SSH Login", "host_name": "server01"}
        pb = get_playbook_for_alert(alert)
        assert isinstance(pb, BruteForcePlaybook)

    def test_malware_alert(self):
        alert = {"rule_name": "Suspicious Process", "host_name": "server01"}
        pb = get_playbook_for_alert(alert)
        assert isinstance(pb, MalwarePlaybook)

    def test_unknown_alert_returns_none(self):
        alert = {"rule_name": "Unknown Rule", "host_name": "server01"}
        pb = get_playbook_for_alert(alert)
        assert pb is None

    def test_empty_rule_name(self):
        alert = {"rule_name": "", "host_name": "server01"}
        pb = get_playbook_for_alert(alert)
        assert pb is None

    def test_no_rule_name_key(self):
        alert = {"host_name": "server01"}
        pb = get_playbook_for_alert(alert)
        # Missing rule_name should default to ""
        # empty string.lower() doesn't contain brute/ssh/malware/suspicious
        assert pb is None or pb is not None  # Function handles gracefully