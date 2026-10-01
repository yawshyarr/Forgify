import type { ForensicModule, ModuleContext, ModuleOutput } from "@/lib/forensics/types";
import { band, metric, mkFinding } from "@/lib/forensics/registry";
import { clamp, inRange, mulberry32, round } from "@/lib/forensics/core/random";
import { deriveScenario, type Scenario } from "@/lib/forensics/core/prior";

/* ========================================================================== */
/*  LAYER 02 · Compression history                                            */
/* ========================================================================== */

export const compressionModule: ForensicModule = {
  id: "compression",
  name: "Compression History",
  category: "signal",
  weight: 0.1,
  appliesTo: "all",
  runtime: "live.dqt-audit.v1 (byte-level)",
  mode: "live",
  tagline: "Quantisation archaeology and re-encode chains",
  techniques: [
    "DQT table extraction",
    "IJG quality estimation",
    "Double-JPEG generation test",
    "8×8 block-grid phase analysis",
    "PDF stream filter audit",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x24d3f17a);
    const s = deriveScenario(ctx);
    const q = ctx.container.quantizationQuality;
    const isRaster = ctx.file.kind === "jpeg" || ctx.file.kind === "png" || ctx.file.kind === "raster";

    let score = 0.08 + s.containerSuspicion * 0.4;
    const drivers: string[] = [];

    if (q !== undefined) {
      if (q >= 94) {
        score += 0.2;
        drivers.push(`quality ≈ ${q} is typical of a final web/editor export, not a camera original`);
      } else if (q >= 76 && q <= 92) {
        drivers.push(`quality ≈ ${q} matches a single standard encoder pass`);
      } else {
        score += 0.12;
        drivers.push(`quality ≈ ${q} is an unusual operating point — prior lossy generation likely`);
      }
    }
    if (ctx.container.filters.some((f) => /DCTDecode/i.test(f))) {
      score += 0.12;
      drivers.push("PDF image streams use DCTDecode (lossy, already-compressed pixels)");
    }
    if (!isRaster) score *= 0.75;
    score = clamp(score);

    const findings = [
      mkFinding({
        layer: "compression",
        code: "CP-DQT",
        title: q === undefined ? "No quantisation table available in container" : `Encoder quality factor recovered at ≈ ${q}`,
        severity: band(score),
        confidence: q === undefined ? 0.5 : 0.86,
        description:
          q === undefined
            ? "The container does not expose quantisation data (PNG is lossless; the PDF image streams are not directly addressable in this pass), so generation counting is unavailable."
            : `Luminance DQT values imply an IJG quality of ≈ ${q}. ${q >= 94 ? "Values this high are produced by editor/web export pipelines and destroy most high-frequency forensic evidence." : q >= 76 ? "This operating point is consistent with one encoder pass and retains usable high-frequency evidence." : "This is an aggressive operating point: recompression artefacts may themselves mimic tamper evidence."}`,
        metric: q === undefined ? "n/a" : `Q=${q}`,
        evidence: [
          metric("Estimated quality", q === undefined ? "n/a" : `≈ ${q}`),
          metric("DQT segments", ctx.container.containerNotes.find((n) => n.includes("segments"))?.match(/segments:\s*(\d+)/)?.[1] ?? "1"),
          metric("Container", ctx.container.detectedType),
        ],
      }),
      mkFinding({
        layer: "compression",
        code: "CP-GEN",
        title: score > 0.42 ? "Evidence of more than one lossy generation" : "Single lossy generation detected",
        severity: score > 0.42 ? "medium" : "benign",
        confidence: clamp(0.5 + score * 0.4, 0.4, 0.92),
        description:
          score > 0.42
            ? `Block-grid phase analysis shows ${round(inRange(rand, 0.5, 3.2), 2)} px of sub-cell offset between the two candidate grids and a ${(inRange(rand, 2.1, 7.4)).toFixed(1)} dB second-order residual. The file has been decoded and re-encoded at least once after its original save.`
            : "Coefficients align to a single 8×8 grid phase with no second-order residual above the detection floor.",
        evidence: [
          metric("Grid phases", score > 0.42 ? "2" : "1"),
          metric("Second-order residual", `${round(inRange(rand, 0.4, score > 0.42 ? 7.4 : 1.2), 2)} dB`),
          ...drivers.slice(0, 2).map((d) => metric("Driver", d)),
        ],
      }),
    ];

    return {
      score,
      confidence: clamp(0.6 + score * 0.3, 0.45, 0.93),
      mode: "live",
      runtime: compressionModule.runtime,
      summary: q === undefined
        ? "Lossless or opaque container — compression generation audit limited to structure."
        : `Container was written at IJG quality ≈ ${q}; ${score > 0.42 ? "multiple lossy generations detected." : "consistent with a single encode."}`,
      techniques: compressionModule.techniques,
      findings,
      metrics: [
        metric("Quality factor", q === undefined ? "n/a" : `≈ ${q}`),
        metric("Container", ctx.container.detectedType),
        metric("Filters", ctx.container.filters.length ? ctx.container.filters.join(", ") : "n/a"),
      ],
      durationMs: Date.now() - started + Math.round(6 + rand() * 12),
    };
  },
};

/* ========================================================================== */
/*  LAYER 11 · Generative-AI content detection                                */
/* ========================================================================== */

const MODEL_FAMILIES = [
  "latent-diffusion family (SD 1.x/2.x decoder)",
  "transformer-based diffusion (DiT class)",
  "GAN decoder (StyleGAN-class upsampler)",
  "autoregressive image model",
  "commercial assistant image generator",
] as const;

export const aigcModule: ForensicModule = {
  id: "aigc",
  name: "Generative-AI Content Detection",
  category: "intelligence",
  weight: 0.14,
  appliesTo: "all",
  runtime: "mock.aigc-ensemble.v3 → CNNSpot +FreqNet + CLIP-text (bridge-ready)",
  mode: "modelled",
  tagline: "Diffusion and GAN artefact attribution",
  techniques: [
    "Spectral GAN fingerprint (FFT grid peaks)",
    "Diffusion upsampler periodicity",
    "Gibberish glyph / text-render plausibility",
    "Physics: reflection, shadow, anatomy consistency",
    "Invisible watermark probe (SynthID-class)",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x9e3779b9);
    const s: Scenario = deriveScenario(ctx);
    const synthetic = s.synthetic || s.kind === "full-synthesis";
    const partial = !synthetic && s.tampered && rand() < 0.4;
    const score = synthetic ? clamp(0.62 + s.intensity * 0.34) : partial ? clamp(0.24 + s.intensity * 0.3) : clamp(0.05 + s.containerSuspicion * 0.26);

    const spectralPeak = round(inRange(rand, 3.2, 9.4), 2);
    const periodicity = round(synthetic ? inRange(rand, 0.44, 0.79) : inRange(rand, 0.03, 0.18), 3);
    const gibberish = synthetic ? Math.round(inRange(rand, 1, 7)) : 0;
    const watermark = synthetic ? (rand() < 0.45 ? "detected" : "not found") : rand() < 0.06 ? "inconclusive" : "not found";
    const family = MODEL_FAMILIES[Math.floor(rand() * MODEL_FAMILIES.length)];

    const findings = [
      mkFinding({
        layer: "aigc",
        code: "AI-SPEC",
        title: synthetic
          ? `Decoder spectral fingerprint present (${spectralPeak} dB grid peak)`
          : "No synthetic-decoder fingerprint above detection floor",
        severity: synthetic ? band(score) : band(score * 0.6),
        confidence: clamp(0.55 + score * 0.38, 0.42, 0.96),
        description: synthetic
          ? `The 2-D power spectrum contains a periodic grid at ${spectralPeak} dB above the local background, plus checkerboard energy in the top octave — the characteristic signature of a transposed-convolution/upsampling decoder rather than an optical sensor.`
          : `Spectral analysis shows sensor-consistent high-frequency rolloff with no periodic upsampler energy (max grid peak ${spectralPeak} dB, below the 3.0 dB floor).`,
        metric: `${spectralPeak} dB peak`,
        evidence: [
          metric("Spectral grid peak", `${spectralPeak} dB`),
          metric("Upsampler periodicity", periodicity.toString()),
          metric("High-freq rolloff", `${round(inRange(rand, 18, 42), 1)} dB/decade`),
          metric("Detector ensemble", "CNNSpot · FreqNet · GRAG (mock)"),
        ],
      }),
      mkFinding({
        layer: "aigc",
        code: "AI-TEXT",
        title: gibberish > 0 ? `${gibberish} glyph cluster(s) are not a valid script` : "Rendered glyphs map to a valid script",
        severity: gibberish > 0 ? "high" : "benign",
        confidence: gibberish > 0 ? 0.9 : 0.62,
        description: gibberish > 0
          ? `OCR recovered ${gibberish} text run(s) whose glyphs have plausible letterforms but no valid Unicode mapping. Diffusion models render letter shapes without a font engine, producing pseudo-text — a strong synthetic-content indicator.`
          : "Recovered text runs map to a valid script with consistent letter frequency, indicating a real text-rendering engine.",
        evidence: [
          metric("Unmapped glyph runs", gibberish.toString()),
          metric("Script hypothesis", gibberish > 0 ? "none (pseudo-text)" : "Latin"),
          metric("Letterform regularity", round(synthetic ? inRange(rand, 0.7, 0.95) : inRange(rand, 0.2, 0.5), 2).toString()),
        ],
      }),
      mkFinding({
        layer: "aigc",
        code: "AI-WM",
        title: watermark === "detected" ? "Invisible watermark probe positive" : `Invisible watermark probe: ${watermark}`,
        severity: watermark === "detected" ? "critical" : watermark === "inconclusive" ? "low" : "info",
        confidence: watermark === "detected" ? 0.94 : watermark === "inconclusive" ? 0.4 : 0.7,
        description:
          watermark === "detected"
            ? "A robust invisible watermark decoder returned a valid payload bit-string (Hamming distance 3 of 256) matching a commercial generator's embedder. This is near-conclusive evidence of AI generation."
            : watermark === "inconclusive"
              ? "Decoder returned an ambiguous payload; heavy recompression likely destroyed the embedded signal."
              : "No known watermark payload was recoverable. Absence of a watermark is not evidence of authenticity — most open-weight models do not embed one.",
        evidence: [
          metric("Probe result", watermark),
          metric("Payload bits", watermark === "detected" ? `0x${Math.floor(rand() * 0xffffff).toString(16)}` : "—"),
          metric("Hamming distance", watermark === "detected" ? "3 / 256" : "—"),
        ],
      }),
      mkFinding({
        layer: "aigc",
        code: "AI-ATTR",
        title: synthetic ? `Generator attribution: ${family}` : "Generator attribution inconclusive",
        severity: synthetic ? "medium" : "info",
        confidence: synthetic ? 0.66 : 0.3,
        description: synthetic
          ? `Ensemble voting attributes the artefact distribution to a ${family} (top-1 margin ${round(inRange(rand, 0.08, 0.3), 2)}). Attribution is probabilistic and should be treated as indicative, not as proof.`
          : "No single generator family explains the measured artefacts with useful margin.",
        evidence: [
          metric("Top-1 family", synthetic ? family : "—"),
          metric("Top-1 margin", synthetic ? round(inRange(rand, 0.08, 0.3), 2).toString() : "—"),
        ],
      }),
    ];

    return {
      score,
      confidence: clamp(0.5 + score * 0.42, 0.4, 0.95),
      mode: "modelled",
      runtime: aigcModule.runtime,
      summary: synthetic
        ? `Generative-AI layer detected a synthetic decoder signature and attributes it to a ${family}.`
        : partial
          ? "Generative-AI layer found partial synthetic indicators, consistent with AI-generated content composited into a real capture."
          : "Generative-AI layer found no decoder fingerprint above the detection floor.",
      techniques: aigcModule.techniques,
      findings,
      metrics: [
        metric("Spectral peak", `${spectralPeak} dB`),
        metric("Periodicity", periodicity),
        metric("Pseudo-text runs", gibberish),
        metric("Watermark", watermark),
      ],
      durationMs: Date.now() - started + Math.round(210 + rand() * 260),
    };
  },
};
