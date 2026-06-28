from security.exfiltration import check_exfiltration


class TestExfiltration:
    def test_clean_text_not_flagged(self):
        assert check_exfiltration("Hello, how are you?") is None

    def test_openai_api_key_detected(self):
        result = check_exfiltration("My key is sk-abc123def456ghi789jkl012")
        assert result is not None
        assert "OpenAI API key" in result

    def test_jwt_token_detected(self):
        result = check_exfiltration("Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8")
        assert result is not None
        assert "JWT token" in result

    def test_private_key_block_detected(self):
        result = check_exfiltration("Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA")
        assert result is not None
        assert "private key" in result

    def test_aws_key_detected(self):
        result = check_exfiltration("Access key: AKIAIOSFODNN7EXAMPLE")
        assert result is not None
        assert "AWS access key" in result

    def test_db_connection_string_detected(self):
        result = check_exfiltration("postgresql://user:password@localhost:5432/mydb")
        assert result is not None
        assert "connection string" in result

    def test_empty_text(self):
        assert check_exfiltration("") is None
        assert check_exfiltration(None) is None
