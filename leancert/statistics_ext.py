from __future__ import annotations

import math
import random
from typing import Iterable


def _beta_fraction(a: float, b: float, x: float) -> float:
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1e-300 if abs(d) < 1e-300 else d
    d = 1.0 / d
    h = d
    for m in range(1, 301):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1e-300 if abs(d) < 1e-300 else d
        c = 1.0 + aa / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1e-300 if abs(d) < 1e-300 else d
        c = 1.0 + aa / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-14:
            break
    return h


def regularized_beta(x: float, a: float, b: float) -> float:
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    front = math.exp(
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        + a * math.log(x) + b * math.log1p(-x)
    )
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _beta_fraction(a, b, x) / a
    return 1.0 - front * _beta_fraction(b, a, 1.0 - x) / b


def beta_quantile(probability: float, a: float, b: float) -> float:
    low, high = 0.0, 1.0
    for _ in range(100):
        middle = (low + high) / 2.0
        if regularized_beta(middle, a, b) < probability:
            low = middle
        else:
            high = middle
    return (low + high) / 2.0


def clopper_pearson(successes: int, trials: int, alpha: float = 0.05) -> tuple[float, float]:
    if trials <= 0:
        raise ValueError("trials must be positive")
    lower = 0.0 if successes == 0 else beta_quantile(alpha / 2, successes, trials - successes + 1)
    upper = 1.0 if successes == trials else beta_quantile(1 - alpha / 2, successes + 1, trials - successes)
    return lower, upper


def stratified_f1_bootstrap(
    rows: list[dict], *, repeats: int = 10_000, seed: int = 20260728,
) -> tuple[float, float]:
    invalid = [row for row in rows if not row["is_expected_valid"]]
    valid = [row for row in rows if row["is_expected_valid"]]
    rng = random.Random(seed)
    values = []
    for _ in range(repeats):
        sample = [rng.choice(invalid) for _ in invalid] + [rng.choice(valid) for _ in valid]
        tp = sum(not row["is_expected_valid"] and not row["is_predicted_valid"] for row in sample)
        fp = sum(row["is_expected_valid"] and not row["is_predicted_valid"] for row in sample)
        fn = sum(not row["is_expected_valid"] and row["is_predicted_valid"] for row in sample)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    values.sort()
    return values[int(0.025 * repeats)], values[min(repeats - 1, int(0.975 * repeats))]
