from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_privilege_escalation_taxonomy.stats import (
    beta_mean,
    cohen_kappa,
    dirichlet_mean,
    ewma,
    quantile,
    wilson,
)


@given(st.integers(min_value=0, max_value=100), st.integers(min_value=1, max_value=100))
def test_wilson_interval_bounds(successes: int, total: int) -> None:
    successes = min(successes, total)
    interval = wilson(successes, total)
    assert 0.0 <= interval.lower <= interval.point <= interval.upper <= 1.0


@pytest.mark.parametrize(
    ("successes", "total", "expected_point"),
    [(0, 10, 0.0), (5, 10, 0.5), (10, 10, 1.0), (1, 4, 0.25), (3, 4, 0.75)],
)
def test_wilson_points(successes: int, total: int, expected_point: float) -> None:
    assert wilson(successes, total).point == expected_point


def test_wilson_rejects_impossible_counts() -> None:
    with pytest.raises(ValueError):
        wilson(2, 1)


def test_wilson_empty_interval_is_unknown() -> None:
    interval = wilson(0, 0)
    assert interval.lower == 0.0
    assert interval.upper == 1.0


def test_beta_cold_start_prior() -> None:
    assert beta_mean(0, 0) == 0.5


@given(st.integers(min_value=0, max_value=50), st.integers(min_value=0, max_value=50))
def test_beta_mean_stays_bounded(successes: int, failures: int) -> None:
    assert 0.0 <= beta_mean(successes, failures) <= 1.0


def test_beta_rejects_negative_counts() -> None:
    with pytest.raises(ValueError):
        beta_mean(-1, 0)


def test_drift_after_five_failures() -> None:
    before = ewma([1.0] * 20, decay=0.3, initial=0.5)
    after = ewma([1.0] * 20 + [0.0] * 5, decay=0.3, initial=0.5)
    assert before > 0.99
    assert after < 0.5


def test_ewma_rejects_invalid_decay() -> None:
    with pytest.raises(ValueError):
        ewma([1.0], decay=0.0)


def test_dirichlet_mean_prefers_larger_count() -> None:
    assert dirichlet_mean({"file": 8, "shell": 0}, "file") > 0.8


def test_dirichlet_rejects_unknown_key() -> None:
    with pytest.raises(KeyError):
        dirichlet_mean({"file": 1}, "shell")


def test_dirichlet_rejects_negative_counts() -> None:
    with pytest.raises(ValueError):
        dirichlet_mean({"file": -1}, "file")


@pytest.mark.parametrize(
    ("values", "probability", "expected"),
    [([1.0, 3.0], 0.5, 2.0), ([1.0, 2.0, 9.0], 0.0, 1.0), ([1.0, 2.0, 9.0], 1.0, 9.0)],
)
def test_quantile(values: list[float], probability: float, expected: float) -> None:
    assert quantile(values, probability) == expected


def test_quantile_rejects_empty_values() -> None:
    with pytest.raises(ValueError):
        quantile([], 0.5)


def test_quantile_rejects_bad_probability() -> None:
    with pytest.raises(ValueError):
        quantile([1.0], 2.0)


def test_cohen_kappa_perfect_agreement() -> None:
    assert cohen_kappa(["a", "b"], ["a", "b"]) == 1.0


def test_cohen_kappa_rejects_unequal_lengths() -> None:
    with pytest.raises(ValueError):
        cohen_kappa(["a"], ["a", "b"])


def test_cohen_kappa_empty_is_perfect() -> None:
    assert cohen_kappa([], []) == 1.0
