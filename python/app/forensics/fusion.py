"""Evidence fusion, verdict mapping and recommendation text (mirrors fusion.ts)."""

from __future__ import annotations

import math


def fuse(layer_results: list[dict], findings: list[dict]) -> dict:
    executed = [layer for layer in layer_results if layer.get("status") != "skipped"]
    raw = sum(layer["weight"] * (0.55 + 0.45 * layer.get("confidence", 0.6)) for layer in executed) or 1.0

    contributions = []
    for layer in layer_results:
        skipped = layer.get("status") == "skipped"
        effective = 0.0 if skipped else layer["weight"] * (0.55 + 0.45 * layer.get("confidence", 0.6)) / raw
        contributions.append(
            {
                "layer": layer["layer"],
                "name": layer["name"],
                "weight": round(effective, 4),
                "score": round(float(layer.get("score", 0)), 4),
                "contribution": round(effective * float(layer.get("score", 0)), 4),
                "status": layer.get("status", "pass"),
            }
        )

    mass = sum(item["contribution"] for item in contributions)
    risk = int(round(_calibrate(mass) * 100))

    scores = [layer.get("score", 0.0) for layer in executed]
    mean = sum(scores) / max(1, len(scores))
    variance = sum((value - mean) ** 2 for value in scores) / max(1, len(scores))
    stdev = math.sqrt(variance)
    agreement = round(max(0.0, 1 - stdev / 0.32), 3)

    mean_confidence = sum(layer.get("confidence", 0.6) for layer in executed) / max(1, len(executed))
    coverage = len(executed) / max(1, len(layer_results))
    critical = len([f for f in findings if f.get("severity") in {"critical", "high"}])
    confidence = round(min(0.98, 0.42 + mean_confidence * 0.34 + agreement * 0.16 + coverage * 0.12 + critical * 0.01), 3)

    top = sorted(contributions, key=lambda item: item["contribution"], reverse=True)[:3]
    rationale = [
        f"Weighted evidence mass = {round(mass, 4)} across {len(executed)} executed layers, "
        f"calibrated through a logistic at midpoint 0.45 → risk {risk}/100.",
        "Dominant contributors: "
        + "; ".join(f"{item['name']} ({round(item['contribution'] * 100, 1)}%)" for item in top)
        + ".",
        f"Layer agreement index {agreement} (σ = {round(stdev, 3)}).",
        f"{len([f for f in findings if f.get('severity') in {'high', 'critical'}])} high-or-critical finding(s) recorded.",
    ]

    return {
        "method": "confidence-weighted linear opinion pool → logistic calibration (midpoint 0.45, slope 5.2)",
        "riskScore": risk,
        "confidence": confidence,
        "agreement": agreement,
        "entropy": 0.0,
        "alertCount": len([f for f in findings if f.get("severity") in {"high", "critical"}]),
        "contributions": contributions,
        "rationale": rationale,
    }


def _calibrate(value: float) -> float:
    result = 1 / (1 + math.exp(-5.2 * (value - 0.45)))
    return min(0.995, max(0.005, result))


def verdict_for(risk: int) -> str:
    if risk >= 86:
        return "forged"
    if risk >= 68:
        return "likely-forged"
    if risk >= 45:
        return "suspicious"
    if risk >= 24:
        return "low-risk"
    return "authentic"


def recommendation(risk: int) -> str:
    if risk >= 68:
        return (
            "Converging evidence from independent layers indicates deliberate alteration. Quarantine the "
            "exhibit, open a formal case, and collect the source system for examiner-led acquisition."
        )
    if risk >= 45:
        return (
            "Multiple layers disagree with the container's declared history. Escalate to a senior examiner "
            "and request the original file before the exhibit is relied upon."
        )
    if risk >= 24:
        return "Minor container anomalies only. Request the original capture from the custodian for confirmation."
    return "No manipulation indicator exceeded threshold. Retain the exhibit and this report in the case file."


def case_code(seed: int) -> str:
    year = 2026
    return f"SF-{year}-{(seed % 900000) + 100000}"
