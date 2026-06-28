from security.rate_limiter import TokenBucketRateLimiter


class TestTokenBucketRateLimiter:
    def test_allows_within_budget(self):
        rl = TokenBucketRateLimiter(window_seconds=60, max_tokens=100)
        assert rl.is_allowed("user-1", 50)
        assert rl.is_allowed("user-1", 50)

    def test_blocks_over_budget(self):
        rl = TokenBucketRateLimiter(window_seconds=60, max_tokens=100)
        assert rl.is_allowed("user-2", 100)
        assert not rl.is_allowed("user-2", 1)

    def test_get_usage(self):
        rl = TokenBucketRateLimiter(window_seconds=60, max_tokens=100)
        rl.is_allowed("user-3", 30)
        rl.is_allowed("user-3", 20)
        assert rl.get_usage("user-3") == 50

    def test_get_remaining(self):
        rl = TokenBucketRateLimiter(window_seconds=60, max_tokens=100)
        rl.is_allowed("user-4", 60)
        assert rl.get_remaining("user-4") == 40

    def test_reset_identity(self):
        rl = TokenBucketRateLimiter(window_seconds=60, max_tokens=100)
        rl.is_allowed("user-5", 100)
        assert not rl.is_allowed("user-5", 1)
        rl.reset("user-5")
        assert rl.is_allowed("user-5", 100)

    def test_independent_per_user(self):
        rl = TokenBucketRateLimiter(window_seconds=60, max_tokens=100)
        rl.is_allowed("user-a", 100)
        assert not rl.is_allowed("user-a", 1)
        assert rl.is_allowed("user-b", 100)
