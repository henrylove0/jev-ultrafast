from jev_ultrafast.agent import Agent, sanitize_url
from qa_release import RESULTS, validate_live_evidence


def test_model_page_redacts_account_identifiers():
    agent = Agent.__new__(Agent)
    agent.redact_values = ("qa@example.com",)
    page = {
        "title": "Welcome qa@example.com",
        "text": "Signed in as qa@example.com",
        "url": "https://example.test/?user=qa@example.com",
        "actions": [{"id": "a", "label": "Account qa@example.com", "kind": "click"}],
    }

    clean = agent._redact_page(page)

    assert "qa@example.com" not in str(clean)
    assert "<redacted>" in clean["text"]
    assert page["text"] == "Signed in as qa@example.com"


def test_model_history_redacts_typed_values():
    agent = Agent.__new__(Agent)
    agent.redact_values = ("qa@example.com",)

    clean = agent._redact_history([{"action": "Email", "text": "qa@example.com"}])

    assert clean == [{"action": "Email", "text": "<redacted>"}]


def test_sensitive_query_values_are_redacted_from_model_page():
    agent = Agent.__new__(Agent)
    agent.redact_values = ()
    page = {
        "title": "Verify",
        "text": "Workspace",
        "url": "https://crm.example.test/verify?loginToken=secret&product=CRM",
        "actions": [],
    }

    assert "secret" not in agent._redact_page(page)["url"]
    assert "loginToken=%3Credacted%3E" in sanitize_url(page["url"])
    assert page["url"].endswith("loginToken=secret&product=CRM")


def test_live_evidence_accepts_one_observed_runtime_identity():
    RESULTS.clear()
    try:
        assert validate_live_evidence(
            {"observedDeployed": {"auth": {"observedAt": "2026-09-23T00:00:00Z", "image": "sha256:abc"}}},
            {"auth": "https://auth.example.test"},
        )
    finally:
        RESULTS.clear()
