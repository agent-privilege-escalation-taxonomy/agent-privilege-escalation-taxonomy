from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from math import sqrt


@dataclass(frozen=True)
class Interval:
    lower: float
    point: float
    upper: float

    def as_dict(self) -> dict[str, float]:
        return {"lower": self.lower, "point": self.point, "upper": self.upper}


def wilson(successes: int, total: int, z: float = 1.96) -> Interval:
    if total <= 0:
        return Interval(0.0, 0.0, 1.0)
    if successes < 0 or successes > total:
        raise ValueError("successes must be between zero and total")
    point = successes / total
    denominator = 1.0 + z * z / total
    centre = point + z * z / (2.0 * total)
    margin = z * sqrt((point * (1.0 - point) / total) + (z * z / (4.0 * total * total)))
    lower = max(0.0, (centre - margin) / denominator)
    upper = min(1.0, (centre + margin) / denominator)
    if successes == 0:
        lower = 0.0
    if successes == total:
        upper = 1.0
    return Interval(lower=lower, point=point, upper=upper)


def beta_mean(
    successes: int,
    failures: int,
    alpha_prior: float = 2.0,
    beta_prior: float = 2.0,
) -> float:
    if successes < 0 or failures < 0:
        raise ValueError("counts must be non-negative")
    alpha = alpha_prior + successes
    beta = beta_prior + failures
    return alpha / (alpha + beta)


def ewma(outcomes: Iterable[float], decay: float = 0.3, initial: float = 0.5) -> float:
    if not 0.0 < decay <= 1.0:
        raise ValueError("decay must be in the interval (0, 1]")
    value = initial
    for outcome in outcomes:
        value = decay * outcome + (1.0 - decay) * value
    return value


def dirichlet_mean(counts: Mapping[str, int], key: str, prior: float = 1.0) -> float:
    if key not in counts:
        raise KeyError(key)
    if any(value < 0 for value in counts.values()):
        raise ValueError("counts must be non-negative")
    total = sum(float(value) + prior for value in counts.values())
    return (float(counts[key]) + prior) / total if total else 0.0


def quantile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise ValueError("at least one value is required")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in the interval [0, 1]")
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower_index = int(position)
    upper_index = min(lower_index + 1, len(ordered) - 1)
    fraction = position - lower_index
    return ordered[lower_index] * (1.0 - fraction) + ordered[upper_index] * fraction


def cohen_kappa(left: Sequence[str], right: Sequence[str]) -> float:
    if len(left) != len(right):
        raise ValueError("label sequences must have equal length")
    if not left:
        return 1.0
    labels = sorted(set(left) | set(right))
    observed = sum(1 for a, b in zip(left, right, strict=True) if a == b) / len(left)
    expected = 0.0
    for label in labels:
        left_rate = sum(1 for value in left if value == label) / len(left)
        right_rate = sum(1 for value in right if value == label) / len(right)
        expected += left_rate * right_rate
    if expected == 1.0:
        return 1.0
    return (observed - expected) / (1.0 - expected)
