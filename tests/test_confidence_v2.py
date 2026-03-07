from duro.core import _confidence


def test_confidence_rewards_invariants_and_consistency():
    hi, _ = _confidence(
        classification="confirmed",
        returncode=0,
        steps_count=6,
        retries=1,
        safety_ok=True,
        invariant_pass_ratio=1.0,
        consistency_ratio=1.0,
    )
    lo, _ = _confidence(
        classification="confirmed",
        returncode=0,
        steps_count=6,
        retries=1,
        safety_ok=False,
        invariant_pass_ratio=0.0,
        consistency_ratio=0.0,
    )
    assert hi > lo


def test_confidence_is_bounded():
    s, _ = _confidence(
        classification="confirmed",
        returncode=0,
        steps_count=999,
        retries=0,
        safety_ok=True,
        invariant_pass_ratio=1.0,
        consistency_ratio=1.0,
    )
    assert 0.0 <= s <= 1.0
