from jev_ultrafast.agent import Agent


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
