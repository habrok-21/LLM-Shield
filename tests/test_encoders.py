from security.encoders import analyze as check_encoded


class TestEncoders:
    def test_clean_text_not_flagged(self):
        assert check_encoded("Where is my Big Mac order?") is None

    def test_hello_world_not_flagged(self):
        assert check_encoded("Hello, how can I help you?") is None

    def test_base64_encoded_detected(self):
        b64 = "ZGVmIGhlbGxvKCk6CiAgICBwcmludCgid29ybGQiKQ=="
        result = check_encoded(b64)
        assert result is not None
        assert "base64" in result.lower()

    def test_hex_encoded_detected(self):
        hex_str = "48656c6c6f20576f726c64" * 2
        result = check_encoded(hex_str)
        assert result is not None
        assert "hex" in result.lower() or "encoded" in result.lower()

    def test_url_encoded_detected(self):
        url = "Hello%20World%21%20This%20is%20a%20test"
        result = check_encoded(url)
        assert result is not None
        assert "url" in result.lower() or "encoded" in result.lower()
