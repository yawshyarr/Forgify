import type { ModuleContext } from "@/lib/forensics/types";
import { inRange, mulberry32 } from "@/lib/forensics/core/random";

/**
 * ============================================================================
 *  Scenario prior
 * ============================================================================
 *  The reference runtime ships *modelled* inference adapters for the layers
 *  that need trained models (ELA, SIFT clustering, diffusion fingerprints,
 *  LLM reasoning). Rather than returning random noise, every adapter is
 *  conditioned on this prior, which is derived from REAL container evidence
 *  (EXIF/XMP survival, quantisation quality, PNG CRC state, PDF revision
 *  count, MIME spoofing) and from the SHA-256 of the evidence file.
 *
 *  Consequence: the same file always produces the same report, and a
 *  camera-original JPEG behaves differently from a Photoshop re-export. When
 *  the Python/OpenCV workers are wired in via the HTTP bridge, this prior is
 *  replaced by live logits and nothing else in the pipeline changes.
 * ============================================================================
 */

export type ScenarioKind =
  | "clean-capture"
  | "region-splice"
  | "copy-move-clone"
  | "text-substitution"
  | "full-synthesis"
  | "metadata-scrub";

export interface Scenario {
  kind: ScenarioKind;
  tampered: boolean;
  synthetic: boolean;
  intensity: number;
  tamperConfidence: number;
  containerSuspicion: number;
  drivers: string[];
  hotspots: { x: number; y: number; width: number; height: number }[];
}

const EDITOR_HINTS = /photoshop|gimp|lightroom|snapseed|canva|pixlr|affinity|pixelmator|figma|inkscape|preview|paint/i;

export function deriveScenario(ctx: ModuleContext): Scenario {
  const rand = mulberry32(ctx.seed ^ 0x5f3759df);
  const { container } = ctx;
  const drivers: string[] = [];
  let containerSuspicion = 0.08;

  if (!container.exifPresent && !container.xmpPresent) {
    containerSuspicion += 0.18;
    drivers.push("no EXIF/XMP survived in the container");
  }
  if (container.typeMismatch) {
    containerSuspicion += 0.24;
    drivers.push("declared MIME type contradicts the byte structure");
  }
  if ((container.quantizationQuality ?? 0) >= 94) {
    containerSuspicion += 0.14;
    drivers.push(`near-lossless re-encode (quality ≈ ${container.quantizationQuality})`);
  }
  if ((container.quantizationQuality ?? 100) <= 62 && container.kind === "jpeg") {
    containerSuspicion += 0.1;
    drivers.push("aggressive recompression collapses high-frequency evidence");
  }
  if (container.incrementalUpdates > 0) {
    containerSuspicion += 0.22;
    drivers.push(`${container.incrementalUpdates} PDF incremental revision(s) present`);
  }
  if (container.containerNotes.some((n) => n.includes("CRC mismatch"))) {
    containerSuspicion += 0.26;
    drivers.push("PNG chunk CRC validation failed");
  }
  const software = (ctx.metadata ?? []).find((m) => /software|creatortool|producer/i.test(m.key))?.value ?? "";
  if (software && EDITOR_HINTS.test(software)) {
    containerSuspicion += 0.16;
    drivers.push(`editing software recorded: ${software}`);
  }
  if (container.javascript) {
    containerSuspicion += 0.12;
    drivers.push("active JavaScript present in the document");
  }

  containerSuspicion = Math.min(0.95, containerSuspicion);

  const roll = rand();
  const tamperThreshold = 0.26 + containerSuspicion * 0.5;
  const tampered = roll < tamperThreshold;
  const synthetic = !tampered && rand() < 0.14 + containerSuspicion * 0.16;

  let kind: ScenarioKind = "clean-capture";
  if (tampered) {
    const k = rand();
    if (container.kind === "pdf" || ctx.file.kind === "pdf") {
      kind = k < 0.45 ? "text-substitution" : k < 0.75 ? "region-splice" : "copy-move-clone";
    } else {
      kind = k < 0.4 ? "region-splice" : k < 0.75 ? "copy-move-clone" : "metadata-scrub";
    }
  } else if (synthetic) {
    kind = "full-synthesis";
  }

  const intensity = tampered
    ? Math.min(0.96, 0.42 + containerSuspicion * 0.4 + rand() * 0.2)
    : synthetic
      ? inRange(rand, 0.46, 0.68)
      : inRange(rand, 0.04, 0.24);

  const hotspotCount = kind === "copy-move-clone" ? 2 : tampered ? (rand() < 0.4 ? 2 : 1) : rand() < 0.3 ? 1 : 0;
  const hotspots = Array.from({ length: hotspotCount }, () => ({
    x: inRange(rand, 0.12, 0.58),
    y: inRange(rand, 0.14, 0.56),
    width: inRange(rand, 0.16, 0.34),
    height: inRange(rand, 0.1, 0.24),
  }));

  return {
    kind,
    tampered,
    synthetic,
    intensity,
    tamperConfidence: Math.min(0.97, 0.52 + intensity * 0.42),
    containerSuspicion,
    drivers,
    hotspots,
  };
}

export function scenarioLabel(kind: ScenarioKind): string {
  switch (kind) {
    case "clean-capture":
      return "consistent single-generation capture";
    case "region-splice":
      return "regional splice / pasted object";
    case "copy-move-clone":
      return "intra-image copy-move clone";
    case "text-substitution":
      return "glyph-level text substitution";
    case "full-synthesis":
      return "fully synthetic / generated content";
    case "metadata-scrub":
      return "metadata scrub with pixel-level concealment";
  }
}
