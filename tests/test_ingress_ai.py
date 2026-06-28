from security.ingress import check_many_shot, get_many_shot_threshold, set_many_shot_threshold


class TestManyShot:
    def test_few_messages_not_flagged(self):
        messages = [{"role": "user", "content": "hi"}]
        assert check_many_shot(messages) is None

    def test_below_threshold_not_flagged(self):
        messages = [{"role": "user", "content": f"msg {i}"} for i in range(10)]
        assert check_many_shot(messages) is None

    def test_above_threshold_flagged(self):
        messages = [{"role": "user", "content": f"msg {i}"} for i in range(25)]
        result = check_many_shot(messages)
        assert result is not None
        assert "excessive message count" in result

    def test_repetitive_turn_pattern_flagged(self):
        turns = []
        for i in range(25):
            turns.append({"role": "user", "content": "a"})
            turns.append({"role": "assistant", "content": "b"})
        result = check_many_shot(turns)
        assert result is not None

    def test_threshold_configurable(self):
        old = get_many_shot_threshold()
        set_many_shot_threshold(5)
        try:
            messages = [{"role": "user", "content": f"msg {i}"} for i in range(6)]
            assert check_many_shot(messages) is not None
        finally:
            set_many_shot_threshold(old)
