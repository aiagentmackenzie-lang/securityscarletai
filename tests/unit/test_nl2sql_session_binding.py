"""SS-009: NL→SQL sessions must be keyed by (user, session_id).

`conversation_manager` was a process-global dict keyed only by the
client-supplied session id, so analyst A could pass analyst B's session id and
inherit B's prior questions/SQL into the prompt — an IDOR on analyst context
and a context-poisoning vector. No result rows crossed, but the model echoed
the other analyst's questions back.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.ai.nl2sql import ConversationManager


class TestSessionsAreBoundToTheAnalyst:
    def test_same_id_different_user_is_a_different_session(self):
        mgr = ConversationManager()
        alice = mgr.get_or_create(owner="alice")
        alice.add_query("show failed logins", "SELECT 1", 0)

        # Bob supplies Alice's session id.
        bob = mgr.get_or_create("session-id-alice", owner="bob")
        assert bob.queries == [], "bob inherited alice's conversation context"

    def test_same_user_same_id_resumes(self):
        mgr = ConversationManager()
        alice = mgr.get_or_create(owner="alice")
        alice.add_query("show failed logins", "SELECT 1", 0)
        again = mgr.get_or_create(alice.session_id, owner="alice")
        assert again is alice
        assert len(again.queries) == 1

    def test_get_is_owner_scoped(self):
        mgr = ConversationManager()
        alice = mgr.get_or_create(owner="alice")
        assert mgr.get(alice.session_id, owner="alice") is alice
        assert mgr.get(alice.session_id, owner="bob") is None

    def test_anonymous_callers_do_not_share_a_namespace(self):
        mgr = ConversationManager()
        ctx = mgr.get_or_create(owner=None)
        assert mgr.get(ctx.session_id, owner="carol") is None

    @pytest.mark.asyncio
    async def test_nl_to_sql_passes_the_owner_through(self):
        from src.ai import nl2sql

        with patch.object(
            nl2sql.conversation_manager,
            "get_or_create",
            wraps=nl2sql.conversation_manager.get_or_create,
        ) as goc:
            with (
                patch.object(nl2sql, "template_match", return_value="SELECT 1 FROM logs"),
                patch("src.ai.nl2sql.add_safety_limits", side_effect=lambda s: s),
                patch("src.ai.nl2sql.estimate_query_cost", AsyncMock(return_value=(1, 10))),
            ):
                await nl2sql.nl_to_sql("how many logs", owner="dave")
        assert goc.call_args.kwargs.get("owner") == "dave"
