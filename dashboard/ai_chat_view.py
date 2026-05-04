"""
AI Chat view for SecurityScarletAI dashboard.

Context-aware security chat powered by Ollama.
Features:
- Natural language conversation with the SIEM
- Context from live alert data, top hosts, critical alerts
- Query templates for common questions
- Prompt injection defense (handled server-side)
- Fallback rule-based responses when Ollama is unavailable

ALL data fetched through ApiClient — NO direct database access.
Loading states: st.status() for AI operations, st.spinner() for template/fetch loads.
"""
import streamlit as st

from dashboard.api_client import ApiError
from dashboard.auth import can_write, get_api_client

# Quick action suggestions for the chat
QUICK_ACTIONS = [
    "What should I investigate first?",
    "Summarize today's security posture",
    "Are there any signs of lateral movement?",
    "Explain the most critical alert",
    "Show me failed login attempts",
    "What hosts are most at risk?",
]


def render_ai_chat():
    """Render the AI chat interface."""
    api = get_api_client()

    st.header("🤖 AI Security Assistant")

    st.markdown("""
    Ask questions about your security data in natural language. The AI assistant
    has context about your current alerts, hosts, and threat landscape.

    **Examples:** "What should I investigate first?", "Are there signs of lateral movement?",
    "Summarize today's security posture"
    """)

    # ─── AI Status ───
    with st.expander("⚙️ AI Status", expanded=False):
        with st.spinner("Loading AI status...", show_time=True):
            try:
                status = api.ai_status()
                triage = status.get("triage", {})
                col1, col2 = st.columns(2)

                with col1:
                    st.metric("Triage Model", triage.get("status", "Unknown"))
                    st.metric("Training Samples", triage.get("samples", 0))
                    if triage.get("accuracy"):
                        st.metric("Model Accuracy", f"{triage['accuracy']:.1%}")

                with col2:
                    ollama_status = status.get("ollama", "Unknown")
                    if ollama_status == "ok":
                        st.success("🟢 Ollama Connected")
                    else:
                        st.warning(f"🟡 Ollama: {ollama_status}")

                    if can_write():
                        if st.button("🔄 Retrain Models", key="retrain_btn"):
                            with st.status(
                                "🔄 Training AI models...",
                                expanded=True
                            ) as train_status:
                                try:
                                    result = api.ai_train()
                                    train_status.update(
                                        label="✅ Training complete",
                                        state="complete"
                                    )
                                    st.toast(
                                        "✅ Model training complete",
                                        icon="✅"
                                    )
                                    st.success(
                                        f"Training complete: "
                                        f"{result.get('message', 'Done')}"
                                    )
                                except ApiError as e:
                                    train_status.update(label="❌ Training failed", state="error")
                                    st.error(f"Training failed: {e.detail}")

            except ApiError as e:
                st.warning(f"AI status unavailable: {e.detail}")

    st.divider()

    # ─── Quick Actions ───
    st.subheader("⚡ Quick Actions")
    cols = st.columns(3)
    for i, action in enumerate(QUICK_ACTIONS):
        with cols[i % 3]:
            if st.button(action, key=f"quick_{i}", use_container_width=True):
                st.session_state.chat_input = action

    st.divider()

    # ─── Chat Interface ───
    st.subheader("💬 Conversation")

    # Initialize chat history
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    # Display chat history
    for msg in st.session_state.chat_history:
        if msg["role"] == "user":
            st.chat_message("user").markdown(msg["content"])
        else:
            st.chat_message("assistant").markdown(msg["content"])

    # Chat input
    user_input = st.chat_input(
        "Ask a security question...",
        key="chat_input_field",
    )

    # Handle quick action pre-fill
    if "chat_input" in st.session_state and st.session_state.chat_input:
        user_input = st.session_state.chat_input
        st.session_state.chat_input = None  # Clear after use

    if user_input:
        # Add user message to history
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        st.chat_message("user").markdown(user_input)

        # Get AI response with status container
        with st.chat_message("assistant"):
            with st.status("🤖 Thinking...", expanded=False) as status:
                try:
                    result = api.ai_chat(user_input)
                    response = result.get("response", result.get("message", "No response available"))  # noqa: E501

                    # Show query results if available
                    query_results = result.get("query_results")
                    if query_results:
                        status.update(label="✅ Response with query results", state="complete")
                    else:
                        status.update(label="✅ Response ready", state="complete")

                    st.markdown(response)

                    # Show query results if available
                    if query_results:
                        with st.expander("📊 Query Results"):
                            import pandas as pd
                            if isinstance(query_results, list) and query_results:
                                df = pd.DataFrame(query_results)
                                st.dataframe(df, use_container_width=True, hide_index=True)
                            else:
                                st.json(query_results)

                    st.session_state.chat_history.append({"role": "assistant", "content": response})

                except ApiError as e:
                    status.update(label="❌ Request failed", state="error")
                    error_msg = f"Sorry, I couldn't process that request. Error: {e.detail}"
                    st.error(error_msg)
                    st.session_state.chat_history.append({"role": "assistant", "content": error_msg})  # noqa: E501

                except Exception as e:
                    status.update(label="❌ Unexpected error", state="error")
                    error_msg = f"Unexpected error: {e}"
                    st.error(error_msg)
                    st.session_state.chat_history.append({"role": "assistant", "content": error_msg})  # noqa: E501

    # ─── NL→SQL Query ───
    st.divider()
    st.subheader("🔍 Natural Language Query")

    st.markdown("""
    Convert natural language questions into SQL queries and execute them directly.
    The query engine has built-in safety controls (injection defense, row limits, timeouts).
    """)

    # Query templates
    with st.expander("📋 Query Templates"):
        with st.spinner("Loading query templates...", show_time=True):
            try:
                templates = api.get_query_templates()
                if templates:
                    for i, tmpl in enumerate(templates[:10]):
                        question = tmpl.get("question", tmpl.get("name", "Unknown"))
                        category = tmpl.get("category", "General")
                        if st.button(f"📁 {category}: {question}", key=f"tmpl_{i}"):
                            st.session_state.nl_query = question
                else:
                    st.info("No templates available — Ollama may be down. Type your question directly below.")  # noqa: E501
            except ApiError:
                st.info("Query templates unavailable — you can still type questions directly.")

    nl_query = st.text_input(
        "Ask a question about your data:",
        placeholder="e.g., Show me all failed logins in the last hour",
        key="nl_query_input",
    )

    # Handle template pre-fill
    if "nl_query" in st.session_state and st.session_state.nl_query:
        nl_query = st.session_state.nl_query
        st.session_state.nl_query = None

    if st.button("▶️ Execute Query", key="execute_query_btn") and nl_query:
        with st.status("🔍 Generating and executing query...", expanded=True) as status:
            try:
                result = api.query(nl_query)

                # Display the generated SQL
                sql = result.get("sql", "")
                if sql:
                    st.code(sql, language="sql")
                    status.update(label="✅ Query executed", state="complete")

                # Display results
                results = result.get("results", [])
                if results:
                    import pandas as pd
                    df = pd.DataFrame(results)
                    st.dataframe(df, use_container_width=True, hide_index=True)
                    st.caption(f"Query returned {len(results)} rows")
                elif result.get("error"):
                    status.update(label="❌ Query error", state="error")
                    st.error(f"Query error: {result['error']}")
                else:
                    status.update(label="ℹ️ No results", state="complete")
                    st.info("Query returned no results")

            except ApiError as e:
                status.update(label="❌ Query failed", state="error")
                st.error(f"Query failed: {e.detail}")
            except Exception as e:
                status.update(label="❌ Unexpected error", state="error")
                st.error(f"Unexpected error: {e}")
