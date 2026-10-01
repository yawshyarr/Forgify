import type { Finding, FusionResult, LayerResult, Verdict } from "@/lib/forensics/types";
import { round } from "@/lib/forensics/core/random";

/** Normalised logistic calibration: midpoint 0.45, slope 5.2. */
function calibrate(x: number): number {
  const v = 1 / (1 + Math.exp(-5.2 * (x - 0.45)));
  return Math.min(0.995, Math.max(0.005, v));
}

export function verdictFor(risk: number): Verdict {
  if (risk >= 86) return "forged";
  if (risk >= 68) return "likely-forged";
  if (risk >= 45) return "suspicious";
  if (risk >= 24) return "low-risk";
  return "authentic";
}

const RECOMMENDATIONS: Record<Verdict, string> = {
  authentic:
    "No manipulation indicator exceeded threshold. Retain the original exhibit and this report in the case file; release with standard chain-of-custody notes.",
  "low-risk":
    "Minor container anomalies only. Accept for preliminary review, but request the original capture from the custodian before the exhibit is used in any formal proceeding.",
  suspicious:
    "Multiple independent layers disagree with the container's declared history. Escalate to a senior examiner, request the original file plus the authoring environment, and treat the exhibit as unverified pending re-acquisition.",
  "likely-forged":
    "Converging evidence from independent layers indicates deliberate alteration. Quarantine the exhibit, open a formal case, and collect the source system for examiner-led acquisition.",
  forged:
    "Direct, machine-checkable manipulation evidence is present (cryptographic or arithmetic failure plus pixel/content corroboration). Preserve the exhibit read-only, notify the counterparty, and prepare the evidence package for legal escalation.",
};

export function fuseEvidence(layers: LayerResult[], findings: Finding[]): FusionResult {
  const executed = layers.filter((l) => l.status !== "skipped");
  const rawWeight = executed.reduce((a, l) => a + l.weight * (0.55 + 0.45 * l.confidence), 0) || 1;
  const contributions = layers.map((l) => {
    const effective = l.status === "skipped" ? 0 : (l.weight * (0.55 + 0.45 * l.confidence)) / rawWeight;
    return {
      layer: l.layer,
      name: l.name,
      weight: round(effective, 4),
      score: round(l.score, 4),
      contribution: round(effective * l.score, 4),
      status: l.status,
    };
  });

  const fused = contributions.reduce((a, c) => a + c.contribution, 0);
  const riskScore = Math.round(calibrate(fused) * 100);

  const scores = executed.map((l) => l.score);
  const mean = scores.reduce((a, b) => a + b, 0) / Math.max(1, scores.length);
  const variance = scores.reduce((a, b) => a + (b - mean) ** 2, 0) / Math.max(1, scores.length);
  const stdev = Math.sqrt(variance);
  const agreement = round(Math.max(0, 1 - stdev / 0.32), 3);

  const meanConfidence = executed.reduce((a, l) => a + l.confidence, 0) / Math.max(1, executed.length);
  const coverage = executed.length / Math.max(1, layers.length);
  const criticalWeight = findings.filter((f) => f.severity === "critical").length * 0.04;
  const confidence = round(
    Math.min(0.98, 0.42 + meanConfidence * 0.34 + agreement * 0.16 + coverage * 0.12 + criticalWeight),
    3,
  );

  const entropy = round(
    -scores.reduce((a, s) => {
      const p = Math.max(1e-6, 1 - Math.abs(s - 0.5) * 2);
      return a + Math.log2(p) * 0.06;
    }, 0),
    3,
  );

  const alertCount = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const top = [...contributions].sort((a, b) => b.contribution - a.contribution).slice(0, 3);
  const corroborating = findings.filter((f) => f.code.startsWith("XC-"));

  const rationale: string[] = [
    `Weighted evidence mass = ${round(fused, 4)} across ${executed.length} executed layers, calibrated through a logistic at midpoint 0.45 → risk ${riskScore}/100.`,
    `Dominant contributors: ${top.map((t) => `${t.name} (${round(t.contribution * 100, 1)}% of fused mass)`).join("; ")}.`,
    `Layer agreement index ${agreement} (σ = ${round(stdev, 3)} across ${scores.length} layer scores) — ${agreement > 0.72 ? "layers are mutually consistent" : agreement > 0.45 ? "partial disagreement, interpret with care" : "layers disagree sharply, which itself warrants manual review"}.`,
    `${alertCount} high-or-critical finding(s) and ${corroborating.length} cross-layer corroboration link(s) were recorded.`,
  ];

  return {
    method: "confidence-weighted linear opinion pool → logistic calibration (midpoint 0.45, slope 5.2)",
    riskScore,
    confidence,
    agreement,
    entropy,
    alertCount,
    contributions,
    rationale,
  };
}

export function buildRecommendation(verdict: Verdict, layers: LayerResult[]): string {
  if (verdict !== "authentic") {
    const worst = [...layers].sort((a, b) => b.score - a.score)[0];
    const extra =
      worst && worst.score > 0.45
        ? ` Primary driver: ${worst.name.toLowerCase()} — ${worst.summary.charAt(0).toLowerCase()}${worst.summary.slice(1)}`
        : "";
    return RECOMMENDATIONS[verdict] + extra;
  }
  return RECOMMENDATIONS.authentic;
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  authentic: "Authentic — no manipulation indicators",
  "low-risk": "Low risk — minor container anomalies",
  suspicious: "Suspicious — multiple layers disagree",
  "likely-forged": "Likely forged — converging evidence",
  forged: "Forged — direct manipulation evidence",
};
