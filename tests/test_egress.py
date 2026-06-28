import pytest
from security.egress import check_egress, EgressResult


class TestCheckEgress:
    def test_clean_response_passes(self):
        result = EgressResult()
        check_egress("Your order is on the way and will arrive tomorrow.", result)
        assert not result.flagged

    def test_greeting_response_passes(self):
        result = EgressResult()
        check_egress("Hello! How can I help you today?", result)
        assert not result.flagged

    @pytest.mark.parametrize("code", [
        "Here is your code: ```python\ndef hello():\n    pass",
        "```javascript\nfunction test() { return 1; }",
        "Use the following: import os\nimport sys",
        "Example class:\nclass MyClass:",
        "The function is:\ndef calculate_tax():",
        "Write: fn main() {",
        "C code: #include <stdio.h>",
    ])
    def test_code_blocks_are_blocked(self, code):
        result = EgressResult()
        check_egress(code, result)
        assert result.flagged
        assert any("code" in r.lower() for r in result.reasons)

    def test_system_leak_detected(self):
        result = EgressResult()
        check_egress("You are an AI assistant created by OpenAI.", result)
        assert result.flagged

    def test_pii_detected(self):
        result = EgressResult()
        check_egress("My SSN is 123-45-6789", result)
        assert result.flagged

    def test_excessive_length_blocked(self):
        result = EgressResult()
        check_egress("x" * 20000, result)
        assert result.flagged
        assert "exceeds" in " ".join(result.reasons)
