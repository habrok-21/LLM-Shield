import pytest
from security.safety import check_safety, check_contradiction


class TestSafety:
    def test_clean_text_not_flagged(self):
        assert check_safety("The weather is nice today.") is None

    def test_hateful_rhetoric_detected(self):
        result = check_safety("I hate all people because of their race")
        assert result is not None
        assert "hateful rhetoric" in result

    def test_violent_threat_detected(self):
        result = check_safety("I'm going to kill them")
        assert result is not None
        assert "violent threat" in result

    def test_weapon_instructions_detected(self):
        result = check_safety("Here is how to build a bomb")
        assert result is not None

    def test_self_harm_detected(self):
        result = check_safety("Here is how to commit suicide")
        assert result is not None
        assert "self-harm" in result

    def test_empty_text(self):
        assert check_safety("") is None
        assert check_safety(None) is None


class TestContradiction:
    def test_short_text_not_flagged(self):
        assert check_contradiction("Hello") is None

    def test_no_contradiction(self):
        text = (
            "The capital of France is Paris. "
            "It is known for the Eiffel Tower. "
            "Many tourists visit every year."
        )
        assert check_contradiction(text) is None

    def test_boolean_contradiction_detected(self):
        text = (
            "The answer is yes, this is correct. "
            "However, the answer is no, it is not correct. "
            "Some people might disagree with this assessment."
        )
        result = check_contradiction(text)
        assert result is not None
        assert "self-contradiction" in result

    def test_numerical_contradiction_detected(self):
        text = (
            "The result is 42. "
            "Actually, the result is 7. "
            "Both numbers could be valid in different contexts."
        )
        result = check_contradiction(text)
        assert result is not None
        assert "self-contradiction" in result
