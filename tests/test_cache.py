from security.cache import SemanticCache


class TestSemanticCache:
    def test_set_and_get_exact_match(self):
        c = SemanticCache(max_entries=10)
        msgs = [{"role": "user", "content": "Hello"}]
        c.set(msgs, {"response": "Hi there"})
        assert c.get(msgs) == {"response": "Hi there"}

    def test_miss_on_different_input(self):
        c = SemanticCache(max_entries=10)
        c.set([{"role": "user", "content": "Hello"}], "resp")
        assert c.get([{"role": "user", "content": "Hi"}]) is None

    def test_ttl_expiry(self):
        c = SemanticCache(max_entries=10, ttl_seconds=0)
        c.set([{"role": "user", "content": "Hello"}], "resp")
        assert c.get([{"role": "user", "content": "Hello"}]) is None

    def test_invalidate(self):
        c = SemanticCache(max_entries=10)
        msgs = [{"role": "user", "content": "Hello"}]
        c.set(msgs, "resp")
        c.invalidate(msgs)
        assert c.get(msgs) is None

    def test_max_entries_eviction(self):
        c = SemanticCache(max_entries=3)
        for i in range(5):
            c.set([{"role": "user", "content": str(i)}], str(i))
        assert c.size <= 3
