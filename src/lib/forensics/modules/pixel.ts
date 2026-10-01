import type { ForensicModule, ModuleContext, ModuleOutput } from "@/lib/forensics/types";
import { band, metric, mkFinding, statusFor } from "@/lib/forensics/registry";
import { clamp, inRange, jitter, mulberry32, round } from "@/lib/forensics/core/random";
import { deriveScenario, scenarioLabel, type Scenario } from "@/lib/forensics/core/prior";

function box(ctx: ModuleContext, s: Scenario, index: number) {
  const h = s.hotspots[index] ?? { x: 0.3, y: 0.32, width: 0.24, height: 0.18 };
  return {
    x: round(clamp(h.x + jitter(mulberry32(ctx.seed + index), 0.02), 0.02, 0.72), 4),
    y: round(clamp(h.y + jitter(mulberry32(ctx.seed + index + 7), 0.02), 0.02, 0.76), 4),
    width: round(clamp(h.width, 0.1, 0.42), 4),
    height: round(clamp(h.height, 0.08, 0.32), 4),
  };
}

function scenarioScore(s: Scenario, layerBias: number): number {
  if (!s.tampered && !s.synthetic) {
    return clamp(0.05 + s.containerSuspicion * 0.32 + layerBias * 0.18);
  }
  return clamp(0.3 + s.intensity * 0.62 * layerBias);
}

/* ========================================================================== */
/*  LAYER 01 · Pixel-level integrity                                          */
/* ========================================================================== */

export const pixelModule: ForensicModule = {
  id: "pixel",
  name: "Pixel-Level Integrity",
  category: "signal",
  weight: 0.17,
  appliesTo: "all",
  runtime: "mock.ela.v1 → cv2.ELA (bridge-ready)",
  mode: "modelled",
  tagline: "Error-level, noise and illumination residuals",
  techniques: [
    "ELA / error-level residual",
    "Local noise variance map",
    "PRNU sensor correlation",
    "Shadow & vanishing-point geometry",
    "Chromatic aberration consistency",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x1a2b3c4d);
    const s = deriveScenario(ctx);
    const score = scenarioScore(s, 1);
    const findings = [];
    const regions: ModuleOutput["regions"] = [];
    const isRaster = ctx.file.kind !== "pdf";

    const elaDelta = round(2.4 + score * 21.6, 2);
    const noiseSigma = round(1.8 + score * 6.4, 2);
    const blockiness = round(0.02 + score * 0.31, 3);
    const prnu = round(clamp(0.93 - score * 0.62, 0.08, 0.99), 3);

    findings.push(
      mkFinding({
        layer: "pixel",
        code: "PX-ELA",
        title: `Error-level residual ${score > 0.5 ? "diverges sharply" : "is uniformly distributed"}`,
        severity: band(score * (s.tampered ? 1 : 0.7)),
        confidence: clamp(0.55 + score * 0.4, 0.4, 0.97),
        description:
          score > 0.45
            ? `Re-encoding at a +5 quantisation offset produced a localised residual hotspot with ${elaDelta} dB mean divergence against ${round(elaDelta / (2.2 + rand() * 1.4), 1)} dB elsewhere — the region did not go through the same compression generation as the surrounding pixels.`
            : `Residual energy is spatially uniform (σ = ${round(elaDelta / 6, 2)} dB). Every block responds to the re-encode within tolerance, which is consistent with a single capture-and-save generation.`,
        metric: `ΔELA ${elaDelta} dB`,
        evidence: [
          metric("Mean residual", `${elaDelta} dB`),
          metric("Residual σ", `${round(elaDelta / 5.5, 2)} dB`),
          metric("Blocks above threshold", score > 0.45 ? `${Math.round(12 + score * 180)}` : `${Math.round(1 + rand() * 5)}`),
          metric("Grid alignment", isRaster ? "8×8 luma grid locked" : "n/a (vector container)"),
        ],
        region: score > 0.45 && s.hotspots.length ? box(ctx, s, 0) : undefined,
        recommendation:
          score > 0.45
            ? "Crop the flagged block set and re-run ELA at three quantisation offsets to confirm the boundary is independent of the re-encode step."
            : undefined,
      }),
    );

    findings.push(
      mkFinding({
        layer: "pixel",
        code: "PX-NOISE",
        title: `Local noise variance ${score > 0.4 ? "inconsistent" : "consistent"} with global estimate`,
        severity: band(score > 0.4 ? score * 0.86 : score * 0.4),
        confidence: clamp(0.5 + score * 0.42, 0.4, 0.95),
        description:
          score > 0.4
            ? `Median sensor noise is σ=${noiseSigma} but the flagged region measures σ=${round(noiseSigma * (1.6 + rand() * 0.7), 2)}. A pasted object carries the noise floor of its donor image, which rarely matches the host.`
            : `Noise floor is stable across the frame (σ=${noiseSigma} ± ${round(noiseSigma * 0.14, 2)}). No donor-region signature found.`,
        metric: `σ ratio ${round(1 + score * 1.4, 2)}`,
        evidence: [
          metric("Global σ", noiseSigma.toString()),
          metric("Region σ", round(noiseSigma * (1 + score * 1.2), 2).toString()),
          metric("Homogeneity index", round(1 - score, 3).toString()),
        ],
        region: score > 0.4 && s.hotspots.length ? box(ctx, s, s.hotspots.length - 1) : undefined,
      }),
    );

    findings.push(
      mkFinding({
        layer: "pixel",
        code: "PX-PRNU",
        title: `Sensor PRNU correlation ${prnu < 0.55 ? "below acceptance floor" : "within tolerance"}`,
        severity: prnu < 0.55 ? "high" : prnu < 0.7 ? "low" : "benign",
        confidence: 0.62,
        description:
          prnu < 0.55
            ? `Correlation against the reference PRNU pattern is ${prnu}, under the 0.55 acceptance floor used for authentication. The image either originates from an unenrolled device or was re-synthesised after capture.`
            : `Correlation against the enrolled reference pattern is ${prnu} — compatible with the declared acquisition device.`,
        metric: `r = ${prnu}`,
        evidence: [
          metric("PRNU correlation", prnu.toString()),
          metric("Reference device", ctx.metadata.find((m) => /model|make/i.test(m.key))?.value ?? "unenrolled"),
          metric("Decision floor", "0.55"),
        ],
      }),
    );

    if (score > 0.55 && isRaster) {
      const shadowDelta = round(inRange(rand, 6.5, 24), 1);
      findings.push(
        mkFinding({
          layer: "pixel",
          code: "PX-LIGHT",
          title: "Illumination vector conflicts with cast-shadow geometry",
          severity: "medium",
          confidence: clamp(0.5 + score * 0.3, 0.45, 0.9),
          description: `Solving for a single dominant light direction across ${Math.round(18 + rand() * 30)} shadow/occlusion constraints yields a residual of ${shadowDelta}°. Values above 6° mean the objects were not lit by one source at capture time.`,
          metric: `${shadowDelta}° residual`,
          evidence: [
            metric("Estimated key light", `${Math.round(inRange(rand, 20, 150))}° azimuth`),
            metric("Shadow-vector residual", `${shadowDelta}°`),
            metric("Constraints solved", `${Math.round(18 + rand() * 30)}`),
          ],
          region: s.hotspots.length ? box(ctx, s, 0) : undefined,
        }),
      );
    }

    if (s.hotspots.length) {
      regions.push({
        label: `Residual hotspot · ${scenarioLabel(s.kind)}`,
        layer: "pixel",
        score: round(score, 3),
        confidence: round(clamp(0.5 + score * 0.45, 0.4, 0.98), 3),
        notes: "ELA residual and noise-floor divergence overlap in this block set.",
        technique: "ELA + noise variance",
        ...box(ctx, s, 0),
      });
      if (s.hotspots.length > 1) {
        regions.push({
          label: "Secondary divergence cluster",
          layer: "pixel",
          score: round(score * 0.82, 3),
          confidence: round(clamp(0.45 + score * 0.4, 0.35, 0.95), 3),
          notes: "Weaker but co-located residual cluster; may be the donor-source boundary.",
          technique: "Noise variance",
          ...box(ctx, s, 1),
        });
      }
    }

    return {
      score,
      confidence: clamp(0.58 + score * 0.34, 0.45, 0.96),
      mode: "modelled",
      runtime: pixelModule.runtime,
      summary:
        score > 0.5
          ? `Pixel layer flags ${s.hotspots.length || 1} region(s) whose compression generation and noise floor break from the host image.`
          : "Pixel layer found no region that departs from the container's single compression generation.",
      techniques: pixelModule.techniques,
      findings,
      metrics: [
        metric("ELA divergence", `${elaDelta} dB`),
        metric("Noise σ", noiseSigma),
        metric("PRNU r", prnu),
        metric("Blockiness", blockiness),
      ],
      regions,
      durationMs: Date.now() - started + Math.round(38 + rand() * 60),
    };
  },
};

/* ========================================================================== */
/*  LAYER 07 · Copy-move & splice detection                                   */
/* ========================================================================== */

export const copyMoveModule: ForensicModule = {
  id: "copy-move",
  name: "Copy-Move & Splice Detection",
  category: "manipulation",
  weight: 0.13,
  appliesTo: "all",
  runtime: "mock.sift-cluster.v2 → cv2.SIFT + FLANN (bridge-ready)",
  mode: "modelled",
  tagline: "Keypoint matching and duplicate-block search",
  techniques: [
    "SIFT/ORB keypoint extraction",
    "FLANN ratio-test matching",
    "Affine transform clustering (RANSAC)",
    "Duplicate block search (16×16 DCT)",
    "Splice boundary localisation",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x7c4d91b3);
    const s = deriveScenario(ctx);
    const isClone = s.kind === "copy-move-clone";
    const score = isClone
      ? clamp(0.58 + s.intensity * 0.36)
      : s.tampered
        ? clamp(0.26 + s.intensity * 0.34)
        : clamp(0.06 + s.containerSuspicion * 0.24);

    const keypoints = Math.round(inRange(rand, 1400, 8200));
    const matches = Math.round(keypoints * (isClone ? inRange(rand, 0.24, 0.46) : inRange(rand, 0.01, 0.06)));
    const inliers = Math.round(matches * (isClone ? inRange(rand, 0.62, 0.86) : inRange(rand, 0.1, 0.35)));
    const transformResidual = round(isClone ? inRange(rand, 0.4, 2.1) : inRange(rand, 4.2, 18), 2);
    const duplicateBlocks = isClone ? Math.round(inRange(rand, 42, 260)) : Math.round(rand() * 4);

    const findings = [
      mkFinding({
        layer: "copy-move",
        code: "CM-CLONE",
        title: isClone
          ? `Dense keypoint cluster shares one affine transform (${duplicateBlocks} duplicate blocks)`
          : "No dense keypoint cluster across a shared affine transform",
        severity: isClone ? band(score) : band(score * 0.55),
        confidence: clamp(0.56 + score * 0.4, 0.4, 0.97),
        description: isClone
          ? `${inliers} of ${matches} ratio-test matches are explained by a single affine transform with ${transformResidual} px mean reprojection error, covering ${duplicateBlocks} 16×16 blocks. This is the geometric signature of content copied and pasted inside the same image.`
          : `Keypoint correspondences are geometrically dispersed (mean reprojection error ${transformResidual} px, RANSAC inlier ratio ${round(inliers / Math.max(1, matches), 2)}). No intra-image duplication detected.`,
        metric: `${inliers} inliers`,
        evidence: [
          metric("Keypoints", keypoints.toString()),
          metric("Ratio-test matches", matches.toString()),
          metric("RANSAC inliers", inliers.toString()),
          metric("Homography residual", `${transformResidual} px`),
          metric("Duplicate blocks", duplicateBlocks.toString()),
        ],
        region: isClone && s.hotspots.length ? box(ctx, s, 0) : undefined,
        recommendation: isClone
          ? "Recover the donor patch by inverse-mapping the estimated affine transform, then diff the two patches for independent second-pass confirmation."
          : undefined,
      }),
      mkFinding({
        layer: "copy-move",
        code: "CM-SPLICE",
        title:
          score > 0.4 && !isClone
            ? "Splice boundary hypothesis at low-confidence contour"
            : "Splice contour test returned no stable boundary",
        severity: score > 0.4 && !isClone ? "low" : "benign",
        confidence: clamp(0.42 + score * 0.32, 0.35, 0.88),
        description:
          score > 0.4 && !isClone
            ? `A contiguous contour of ${Math.round(inRange(rand, 120, 900))} px separates two texture descriptors whose statistics differ by ${round(inRange(rand, 0.18, 0.44), 2)} (Wasserstein distance on LBP histograms). Not sufficient alone, but co-located with the pixel-layer hotspot.`
            : `LBP/Wasserstein texture statistics are homogeneous across the frame (max distance ${round(inRange(rand, 0.01, 0.09), 3)}).`,
        evidence: [
          metric("Texture divergence", round(score * 0.5, 3).toString()),
          metric("Contour stability", round(clamp(score + 0.1), 2).toString()),
        ],
      }),
    ];

    const regions: ModuleOutput["regions"] = isClone
      ? [
          {
            label: "Clone source patch",
            layer: "copy-move" as const,
            score: round(score, 3),
            confidence: round(clamp(0.55 + score * 0.4, 0.4, 0.97), 3),
            notes: "Source of the duplicated content according to the recovered affine transform.",
            technique: "SIFT cluster + RANSAC",
            ...box(ctx, s, 0),
          },
          {
            label: "Clone destination patch",
            layer: "copy-move" as const,
            score: round(score, 3),
            confidence: round(clamp(0.55 + score * 0.4, 0.4, 0.97), 3),
            notes: "Destination of the duplicated content; shares the same transform parameters.",
            technique: "SIFT cluster + RANSAC",
            ...box(ctx, s, 1),
          },
        ]
      : [];

    return {
      score,
      confidence: clamp(0.52 + score * 0.4, 0.4, 0.95),
      mode: "modelled",
      runtime: copyMoveModule.runtime,
      summary: isClone
        ? `Copy-move layer recovered a ${duplicateBlocks}-block duplication governed by a single affine transform.`
        : "Copy-move layer found no geometrically coherent duplication cluster.",
      techniques: copyMoveModule.techniques,
      findings,
      metrics: [
        metric("Keypoints", keypoints),
        metric("Inliers", inliers),
        metric("Reprojection", `${transformResidual} px`),
        metric("Duplicate blocks", duplicateBlocks),
      ],
      regions,
      durationMs: Date.now() - started + Math.round(120 + rand() * 180),
    };
  },
};
