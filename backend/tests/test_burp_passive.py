
from backend.scanner.burp_passive import analyze_history


def test_burp_passive_sql_indicator():
    result = {
        "content": [
            {
                "type": "text",
                "text": (
                    '{"url":"https://target.test/login",'
                    '"response":"MySQL syntax error near SELECT"}'
                ),
            }
        ]
    }

    findings = analyze_history(result, "https://target.test")

    assert len(findings) == 1
    assert "SQL error indicator" in findings[0]["title"]
    assert findings[0]["tool"] == "burp"
    assert findings[0]["confidence"] == "low"


def test_burp_passive_ignores_other_target():
    result = {
        "content": [
            {
                "type": "text",
                "text": (
                    '{"url":"https://other.test/login",'
                    '"response":"MySQL syntax error"}'
                ),
            }
        ]
    }

    assert analyze_history(result, "https://target.test") == []
