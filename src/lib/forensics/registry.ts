import type { EvidencePair, Finding, LayerId, Severity } from "@/lib/forensics/types";

export interface LayerDescriptor {
  id: LayerId;
  name: string;
  short: string;
  category: "signal" | "container" | "content" | "manipulation" | "intelligence";
  weight: number;
  tagline: string;
  description: string;
  techniques: string[];
  accent: string;
  glyph: string;
}

/**
 * Single source of truth for the eleven-layer stack. The engine reads the
 * fusion weights from here, the API exposes it at `GET /api/layers`, and the
 * landing page renders the same definitions — so docs, UI and runtime never
 * drift apart.
 */
export const LAYERS: LayerDescriptor[] = [
  {
    id: "pixel",
    name: "Pixel-Level Integrity",
    short: "Pixel",
    category: "signal",
    weight: 0.17,
    tagline: "Error-level, noise and illumination residuals",
    description:
      "Re-compresses the evidence at a shifted quantisation scale and measures where the residual energy diverges. Local noise sigma, sensor PRNU correlation, chromatic aberration and shadow-vector geometry are compared per block to expose splices that survive visual inspection.",
    techniques: ["ELA / error-level residual", "Noise variance map", "PRNU correlation", "Shadow & vanishing-point geometry", "Chromatic aberration consistency"],
    accent: "#1a3ff5",
    glyph: "PX",
  },
  {
    id: "compression",
    name: "Compression History",
    short: "Compress",
    category: "signal",
    weight: 0.1,
    tagline: "Quantisation archaeology and re-encode chains",
    description:
      "Recovers the quantisation tables stored in the container, estimates the IJG quality factor, and tests whether the coefficients are consistent with a single encoding generation. Detects double-compression, quality drift and lossy PDF image re-exports.",
    techniques: ["DQT quality estimation", "Double-JPEG detection", "8×8 block-grid alignment", "PDF filter chain audit"],
    accent: "#2f5cff",
    glyph: "CQ",
  },
  {
    id: "metadata",
    name: "Metadata Forensics",
    short: "Metadata",
    category: "container",
    weight: 0.12,
    tagline: "EXIF / XMP / document-info consistency",
    description:
      "Parses EXIF, XMP and PDF document-info dictionaries straight from the byte stream, then cross-checks timestamps, software tags, device identifiers and GPS claims against each other and against the container's physical characteristics.",
    techniques: ["EXIF tag extraction", "XMP history graph", "Timestamp paradox detection", "Software/device fingerprinting", "GPS plausibility"],
    accent: "#06b6d4",
    glyph: "MD",
  },
  {
    id: "provenance",
    name: "Provenance & Chain of Custody",
    short: "Provenance",
    category: "container",
    weight: 0.1,
    tagline: "C2PA content credentials and manifest trust",
    description:
      "Searches for C2PA / JUMBF content-credential manifests, validates the signed hash of the bound asset, resolves the trust chain to a known signatory and records whether the custody trail is complete, broken or entirely absent.",
    techniques: ["C2PA manifest discovery", "JUMBF box walk", "Certificate trust resolution", "Manifest-to-asset hash binding"],
    accent: "#0ea5a5",
    glyph: "PR",
  },
  {
    id: "ocr",
    name: "OCR & Glyph Analysis",
    short: "OCR",
    category: "content",
    weight: 0.08,
    tagline: "Text recovery plus glyph-level anomalies",
    description:
      "Recovers the text layer with per-block confidence, then inspects glyph geometry for substitution: inconsistent stroke weight, baseline drift, kerning jumps and font-family mixing inside a single text run.",
    techniques: ["Confidence-weighted OCR", "Font clustering", "Baseline & kerning residual", "Digit-glyph substitution test"],
    accent: "#133a6f",
    glyph: "OC",
  },
  {
    id: "layout",
    name: "Layout & Geometry",
    short: "Layout",
    category: "content",
    weight: 0.07,
    tagline: "Grid alignment, margins and logo geometry",
    description:
      "Reconstructs the document's underlying grid from detected rules, table borders and text columns, then measures how far individual elements deviate. Aspect-ratio distortion of logos and seals is a strong paste indicator.",
    techniques: ["Grid reconstruction", "Margin/symmetry analysis", "Logo aspect-ratio test", "Interline spacing variance"],
    accent: "#3a66a0",
    glyph: "LY",
  },
  {
    id: "copy-move",
    name: "Copy-Move & Splice Detection",
    short: "Copy-Move",
    category: "manipulation",
    weight: 0.13,
    tagline: "Keypoint matching and duplicate-block search",
    description:
      "Extracts local descriptors, matches them against a KD-tree and clusters the correspondences. Dense clusters that share a single affine transform indicate copy-move forgery; correspondences with inconsistent transforms indicate splicing from a second source.",
    techniques: ["SIFT/ORB keypoint matching", "Patched block matching", "Affine transform clustering", "Splice-boundary localisation"],
    accent: "#1630d8",
    glyph: "CM",
  },
  {
    id: "signature",
    name: "Signature & Seal Forensics",
    short: "Signature",
    category: "manipulation",
    weight: 0.06,
    tagline: "Cryptographic signatures and wet-ink stamps",
    description:
      "Verifies PAdES/PKCS#7 byte ranges in PDFs, checks whether the digest still covers the current revision, and analyses wet-ink or stamped signatures as raster objects — looking for hard edges, uniform alpha and background haloing that betray a paste.",
    techniques: ["/ByteRange digest verification", "Revocation & LTV check", "Signature raster analysis", "Seal/stamp geometry"],
    accent: "#55637a",
    glyph: "SG",
  },
  {
    id: "qr-barcode",
    name: "QR / Barcode Verification",
    short: "QR / Code",
    category: "content",
    weight: 0.05,
    tagline: "Payload resolution and domain reputation",
    description:
      "Decodes QR codes and barcodes, then evaluates the payload: domain age heuristics, redirect chains, shortener usage, mismatch between the encoded value and human-readable text, and error-correction capacity consumed by overwriting.",
    techniques: ["QR/Code-128 decode", "Payload domain reputation", "Printed-vs-encoded cross-check", "ECC block integrity"],
    accent: "#1d4a86",
    glyph: "QR",
  },
  {
    id: "semantic",
    name: "Semantic Consistency",
    short: "Semantic",
    category: "intelligence",
    weight: 0.08,
    tagline: "Arithmetic, entity and terminology coherence",
    description:
      "A language model reads the recovered text and checks the things pixels cannot see: amount-in-words versus digits, line-item totals, date ordering, tax arithmetic, entity identifier formats, jurisdiction terminology and anachronistic phrasing.",
    techniques: ["LLM cross-field reasoning", "Numeric/tax recomputation", "Entity-format validation", "Terminology anachronism scan"],
    accent: "#5c85ff",
    glyph: "SE",
  },
  {
    id: "aigc",
    name: "Generative-AI Content Detection",
    short: "AIGC",
    category: "intelligence",
    weight: 0.14,
    tagline: "Diffusion and GAN artefact attribution",
    description:
      "Tests for the spectral and periodic fingerprints left by diffusion and GAN decoders, measures text-rendering plausibility, physics/geometry consistency and watermark probes, and attributes the most likely generator family when a signal is present.",
    techniques: ["Spectral GAN fingerprint", "Diffusion periodicity", "Gibberish glyph detection", "Physics & reflection consistency", "Invisible watermark probe"],
    accent: "#071122",
    glyph: "AI",
  },
];

export const LAYER_MAP: Record<LayerId, LayerDescriptor> = LAYERS.reduce(
  (acc, layer) => {
    acc[layer.id] = layer;
    return acc;
  },
  {} as Record<LayerId, LayerDescriptor>,
);

export const SEVERITY_ORDER: Severity[] = ["benign", "info", "low", "medium", "high", "critical"];

let findingSeq = 0;

export function mkFinding(input: {
  layer: LayerId;
  code: string;
  title: string;
  severity: Severity;
  confidence: number;
  description: string;
  evidence?: EvidencePair[];
  metric?: string;
  region?: Finding["region"];
  recommendation?: string;
}): Finding {
  findingSeq += 1;
  return {
    id: `F-${input.code}-${findingSeq.toString().padStart(3, "0")}`,
    evidence: input.evidence ?? [],
    ...input,
  };
}

export function metric(label: string, value: string | number): EvidencePair {
  return { label, value: typeof value === "number" ? value.toString() : value };
}

/** Maps a raw suspicion score to a severity band used across the UI. */
export function band(score: number): Severity {
  if (score >= 0.82) return "critical";
  if (score >= 0.66) return "high";
  if (score >= 0.45) return "medium";
  if (score >= 0.26) return "low";
  return score >= 0.14 ? "info" : "benign";
}

export function statusFor(score: number): "pass" | "review" | "alert" {
  if (score >= 0.5) return "alert";
  if (score >= 0.28) return "review";
  return "pass";
}
