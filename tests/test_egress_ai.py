from security.egress import check_length_ratio, get_max_length_ratio, set_max_length_ratio


class TestLengthRatio:
    def test_no_prompt(self):
        assert check_length_ratio(0, 100) is None

    def test_no_response(self):
        assert check_length_ratio(100, 0) is None

    def test_normal_ratio_not_flagged(self):
        assert check_length_ratio(100, 50) is None

    def test_high_ratio_flagged(self):
        result = check_length_ratio(10, 5000)
        assert result is not None
        assert "length ratio anomaly" in result

    def test_threshold_configurable(self):
        old = get_max_length_ratio()
        set_max_length_ratio(10)
        try:
            assert check_length_ratio(100, 2000) is not None
            assert check_length_ratio(100, 500) is None
        finally:
            set_max_length_ratio(old)
