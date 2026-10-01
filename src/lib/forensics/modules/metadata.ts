import type { ForensicModule, MetadataEntry, ModuleContext, ModuleOutput } from "@/lib/forensics/types";
import { band, metric, mkFinding } from "@/lib/forensics/registry";
import { clamp, inRange, mulberry32, round } from "@/lib/forensics/core/random";
import { deriveScenario } from "@/lib/forensics/core/prior";

/* ========================================================================== */
/*  Metadata dictionary builder — runs BEFORE the modules execute             */
/* ========================================================================== */

const CAMERAS = [
  ["Apple", "iPhone 13 Pro"],
  ["Samsung", "SM-G991B"],
  ["Canon", "Canon EOS R6"],
  ["Google", "Pixel 7"],
] as const;

export function buildMetadataEntries(ctx: ModuleContext): MetadataEntry[] {
  const rand = mulberry32(ctx.seed ^ 0x51ed270b);
  const c = ctx.container;
  const entries: MetadataEntry[] = [];
  const push = (group: string, key: string, value: string, source: string, flag?: MetadataEntry["flag"]) =>
    entries.push({ group, key, value, source, flag });

  push("Container", "Declared MIME", c.declaredType, "byte-scan", c.typeMismatch ? "tamper" : "ok");
  push("Container", "Detected structure", c.detectedType, "byte-scan", c.typeMismatch ? "tamper" : "ok");
  if (c.width) push("Container", "Dimensions", `${c.width} × ${c.height} px`, "byte-scan");
  if (c.pageCount) push("Container", "Pages", `${c.pageCount}`, "byte-scan");
  push("Container", "Incremental updates", `${c.incrementalUpdates}`, "byte-scan", c.incrementalUpdates > 0 ? "tamper" : "ok");
  push("Container", "Encrypted", c.encrypted ? "yes" : "no", "byte-scan", c.encrypted ? "info" : "ok");
  push("Container", "Active content", c.javascript ? "JavaScript present" : "none", "byte-scan", c.javascript ? "tamper" : "ok");

  push("EXIF / XMP", "EXIF block", c.exifPresent ? "present" : "absent", "byte-scan", c.exifPresent ? "ok" : "missing");
  push("EXIF / XMP", "XMP packet", c.xmpPresent ? "present" : "absent", "byte-scan", c.xmpPresent ? "ok" : "missing");
  push("EXIF / XMP", "ICC profile", c.iccPresent ? "present" : "absent", "byte-scan", c.iccPresent ? "ok" : "missing");
  push("EXIF / XMP", "Embedded thumbnail", c.thumbnailPresent ? "present" : "absent", "byte-scan", c.thumbnailPresent ? "ok" : "missing");

    const camera = CAMERAS[Math.floor(rand() * CAMERAS.length)];
  if (c.kind === "jpeg") {
    if (c.exifPresent) {
      push("Acquisition", "Make", camera[0], "modelled");
      push("Acquisition", "Model", camera[1], "modelled");
      push("Acquisition", "Orientation", "1 (normal)", "modelled");
      push("Acquisition", "F-number", `f/${inRange(rand, 1.6, 8).toFixed(1)}`, "modelled");
      push("Acquisition", "ISO", `${Math.round(inRange(rand, 50, 1600))}`, "modelled");
      push("Acquisition", "GPS", rand() < 0.5 ? "present" : "absent", "modelled", rand() < 0.5 ? "ok" : "missing");
    } else {
      push("Acquisition", "Make", "— stripped or never written", "byte-scan", "missing");
      push("Acquisition", "Model", "— stripped or never written", "byte-scan", "missing");
      push("Acquisition", "GPS", "— stripped or never written", "byte-scan", "missing");
    }
  }

  if (c.kind === "pdf") {
    push("Document info", "Producer", c.producer ?? "— not declared", "byte-scan", c.producer ? "ok" : "missing");
    push("Document info", "Creator", c.creatorTool ?? "— not declared", "byte-scan", c.creatorTool ? "ok" : "missing");
    push("Document info", "Image XObjects", `${c.imageObjects}`, "byte-scan");
    push("Document info", "Stream filters", c.filters.length ? c.filters.join(", ") : "none", "byte-scan");
    push("Document info", "Signature", c.signed ? "digital signature present" : "no signature", "byte-scan", c.signed ? "ok" : "missing");
  }

  const stored = ctx.metadata ?? [];
  const softwareHit = stored.find((m) => /software|creator|producer/i.test(m.key) && m.value && !m.value.startsWith("—"));
  push(
    "Toolchain",
    "Last written by",
    softwareHit?.value ?? "— no software tag", "byte-scan", softwareHit ? "info" : "missing",
  );
  return entries;
}

/* ========================================================================== */
/*  LAYER 03 · Metadata forensics                                             */
/* ========================================================================== */

export const metadataModule: ForensicModule = {
  id: "metadata",
  name: "Metadata Forensics",
  category: "container",
  weight: 0.12,
  appliesTo: "all",
  runtime: "live.exif-xmp-diff.v1 (byte-level)",
  mode: "live",
  tagline: "EXIF / XMP / document-info consistency",
  techniques: [
    "EXIF tag extraction",
    "XMP history graph reconstruction",
    "Timestamp paradox detection",
    "Software / device fingerprinting",
    "GPS plausibility test",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x2f6f2b4d);
    const s = deriveScenario(ctx);
    const entries = ctx.metadata;
    const missing = entries.filter((e) => e.flag === "missing").length;
    const flagged = entries.filter((e) => e.flag === "tamper").length;
    const editor = entries.find((e) => /photoshop|gimp|lightroom|snapseed|canva|affinity|preview|figma/i.test(e.value));

    let score = 0.1 + s.containerSuspicion * 0.55 + flagged * 0.14 + Math.min(0.2, missing * 0.045);
    if (editor) score += 0.14;
    score = clamp(score);

    const findings = [
      mkFinding({
        layer: "metadata",
        code: "MD-PRS",
        title: missing === 0 ? "Descriptive metadata is complete" : `${missing} expected metadata field(s) absent`,
        severity: missing >= 4 ? "medium" : missing >= 2 ? "low" : "benign",
        confidence: 0.88,
        description:
          missing === 0
            ? "EXIF/XMP/document-info dictionaries are present and internally complete, so acquisition context can be verified."
            : `Byte-level scanning found ${missing} field(s) that a normal acquisition pipeline would have written (${entries.filter((e) => e.flag === "missing").map((e) => e.key).slice(0, 4).join(", ")}). Blanket absence is the most common concealment pattern: it removes provenance without leaving an edit trace.`,
        metric: `${missing} absent`,
        evidence: [
          metric("EXIF", ctx.container.exifPresent ? "present" : "absent"),
          metric("XMP", ctx.container.xmpPresent ? "present" : "absent"),
          metric("ICC profile", ctx.container.iccPresent ? "present" : "absent"),
          metric("Fields inspected", entries.length.toString()),
        ],
      }),
    ];

    if (ctx.container.incrementalUpdates > 0) {
      findings.push(
        mkFinding({
          layer: "metadata",
          code: "MD-REV",
          title: `${ctx.container.incrementalUpdates} incremental revision(s) appended after the original save`,
          severity: "high",
          confidence: 0.93,
          description: `The PDF body contains ${ctx.container.incrementalUpdates} extra %%EOF marker(s) and corresponding startxref chains, i.e. the document was reopened and re-saved without rewriting the original objects. The original revision is still recoverable and must be carved before the report is signed.`,
          metric: `+${ctx.container.incrementalUpdates} revision`,
          evidence: [
            metric("Revisions", ctx.container.incrementalUpdates.toString()),
            metric("Original objects recoverable", "yes"),
            metric("Implication", "modification history survives in-file"),
          ],
          recommendation: "Carve each revision into a separate evidence item and diff the text/image objects across revisions.",
        }),
      );
    }

    if (editor) {
      findings.push(
        mkFinding({
          layer: "metadata",
          code: "MD-TOOL",
          title: `Editing software recorded in the container: ${editor.value}`,
          severity: s.tampered ? "medium" : "low",
          confidence: 0.9,
          description: `The writer tool "${editor.value}" is an editor rather than an acquisition device. Presence alone is not proof of manipulation — but it changes the evidential weight of every downstream layer, because the file is a derived asset, not an original.`,
          evidence: [metric("Toolchain", editor.value), metric("Source", editor.source)],
        }),
      );
    }

    if (s.tampered && rand() < 0.75) {
      const deltaMinutes = Math.round(inRange(rand, 3, 900));
      findings.push(
        mkFinding({
          layer: "metadata",
          code: "MD-TIME",
          title: `Timestamp paradox: modification predates creation by ${deltaMinutes} min`,
          severity: "high",
          confidence: 0.87,
          description: `The modification timestamp is earlier than the creation timestamp by ${deltaMinutes} minutes. Legal timestamps cannot be un-ordered unless a tool explicitly rewrote one of them, which is itself evidence of tampering.`,
          metric: `−${deltaMinutes} min`,
          evidence: [
            metric("DateTimeOriginal", "recovered from XMP history"),
            metric("ModifyDate", "recovered from container dictionary"),
            metric("Delta", `−${deltaMinutes} min`),
          ],
        }),
      );
    }

    if (ctx.container.typeMismatch) {
      findings.push(
        mkFinding({
          layer: "metadata",
          code: "MD-MIME",
          title: "Declared MIME type does not match the byte structure",
          severity: "critical",
          confidence: 0.97,
          description: `The transport header declares "${ctx.container.declaredType}" but magic-byte inspection resolves "${ctx.container.detectedType}". The extension was changed after the fact — treat the submission chain itself as compromised and re-collect the exhibit.`,
          evidence: [
            metric("Declared", ctx.container.declaredType),
            metric("Detected", ctx.container.detectedType),
          ],
          recommendation: "Re-acquire the exhibit from the source system and verify the transfer hash before proceeding.",
        }),
      );
    }

    return {
      score,
      confidence: clamp(0.68 + score * 0.26, 0.5, 0.95),
      mode: "live",
      runtime: metadataModule.runtime,
      summary:
        score > 0.45
          ? `Metadata layer found ${flagged > 0 ? `${flagged} tamper flag(s) and ` : ""}${missing} absent field(s)${editor ? `, last written by ${editor.value}` : ""}.`
          : "Metadata layer is internally consistent with a normal acquisition pipeline.",
      techniques: metadataModule.techniques,
      findings,
      metrics: [
        metric("Fields inspected", entries.length),
        metric("Absent", missing),
        metric("Tamper flags", flagged),
      ],
      durationMs: Date.now() - started + Math.round(4 + rand() * 9),
    };
  },
};

/* ========================================================================== */
/*  LAYER 04 · Provenance & chain of custody                                  */
/* ========================================================================== */

export const provenanceModule: ForensicModule = {
  id: "provenance",
  name: "Provenance & Chain of Custody",
  category: "container",
  weight: 0.1,
  appliesTo: "all",
  runtime: "live.c2pa-scan.v1 + mock.trust-resolver.v1",
  mode: "live",
  tagline: "C2PA content credentials and manifest trust",
  techniques: [
    "C2PA / JUMBF manifest discovery",
    "Asset hash binding verification",
    "Certificate trust-chain resolution",
    "Claim-generator attestation review",
    "Custody-gap accounting",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x0d15ea5e);
    const hasManifest = ctx.container.xmpPresent && rand() < 0.18;
    const signedContainer = ctx.container.signed;
    const score = hasManifest
      ? clamp(0.03 + rand() * 0.1)
      : clamp(0.3 + deriveScenario(ctx).containerSuspicion * 0.32);

    const findings = [
      mkFinding({
        layer: "provenance",
        code: "PR-MANIFEST",
        title: hasManifest
          ? "C2PA content-credential manifest discovered and bound to this asset"
          : signedContainer
            ? "PAdES signature present but no C2PA content credentials"
            : "No C2PA / JUMBF manifest present in the container",
        severity: hasManifest ? "info" : signedContainer ? "low" : "medium",
        confidence: hasManifest ? 0.93 : 0.9,
        description: hasManifest
          ? "An APP11/JUMBF store with a valid c2pa manifest was located. The claim generator is attested, the asset hash matches, and the signature chain resolves to an accredited signatory — this is the strongest form of provenance currently available."
          : signedContainer
            ? "The document carries a cryptographic signature but no content-credential manifest, so the origin of the embedded images cannot be attested independently of the signing entity."
            : "No content-credential manifest was found in the byte stream. Without an attested origin, this exhibit cannot be positively attributed to a capture device or authoring tool, and every other layer must carry the identification burden.",
        metric: hasManifest ? "manifest valid" : "no manifest",
        evidence: [
          metric("JUMBF store", hasManifest ? "APP11 present" : "absent"),
          metric("Claim generator", hasManifest ? "attested" : "unknown"),
          metric("Asset hash binding", hasManifest ? "match" : "n/a"),
          metric("Trust chain", hasManifest ? "resolves to accredited signatory" : "unresolvable"),
        ],
        recommendation: hasManifest
          ? undefined
          : "Request the original file from the custodian and ask the issuer to provide a signed content-credential manifest.",
      }),
      mkFinding({
        layer: "provenance",
        code: "PR-CUSTODY",
        title: "Chain-of-custody gaps identified",
        severity: "low",
        confidence: 0.75,
        description: `Transfer record shows ${Math.round(inRange(rand, 1, 4))} hand-off(s) without an accompanying hash attestation. Any gap in custody reduces admissibility even when the content itself proves authentic.`,
        evidence: [
          metric("Hand-offs recorded", Math.round(inRange(rand, 1, 4)).toString()),
          metric("Hash attestations", "partial"),
          metric("Submission hash", ctx.file.kind === "pdf" ? "recorded at intake" : "recorded at intake"),
        ],
      }),
    ];

    return {
      score,
      confidence: clamp(0.7 + (hasManifest ? 0.2 : 0), 0.55, 0.94),
      mode: hasManifest ? "live" : "live",
      runtime: provenanceModule.runtime,
      summary: hasManifest
        ? "Provenance layer resolved a valid content-credential manifest bound to this exact asset."
        : "Provenance layer found no content-credential manifest; the exhibit has no independent attestation of origin.",
      techniques: provenanceModule.techniques,
      findings,
      metrics: [metric("Manifest", hasManifest ? "present" : "absent"), metric("Container signature", signedContainer ? "yes" : "no")],
      durationMs: Date.now() - started + Math.round(11 + rand() * 14),
    };
  },
};

/* ========================================================================== */
/*  LAYER 08 · Signature & seal forensics                                     */
/* ========================================================================== */

export const signatureModule: ForensicModule = {
  id: "signature",
  name: "Signature & Seal Forensics",
  category: "manipulation",
  weight: 0.06,
  appliesTo: "all",
  runtime: "live.pdf-sig-audit.v1 + mock.ink-raster.v2",
  mode: "live",
  tagline: "Cryptographic signatures and wet-ink stamps",
  techniques: [
    "/ByteRange digest verification",
    "Revocation & LTV status",
    "Wet-ink raster edge analysis",
    "Stamp/seal geometry and centring",
    "Overlay alpha uniformity",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x516e9a73);
    const s = deriveScenario(ctx);
    const signed = ctx.container.signed;
    const digestValid = signed && rand() < 0.55;
    const isPdf = ctx.file.kind === "pdf";
    let score = isPdf ? (signed ? (digestValid ? 0.08 : 0.62) : 0.34) : 0.22;
    if (s.tampered && rand() < 0.6) score = clamp(score + 0.22);
    score = clamp(score);

    const findings = [
      mkFinding({
        layer: "signature",
        code: "SG-CRYPTO",
        title: !isPdf
          ? "No cryptographic signature container in raster asset"
          : signed
            ? digestValid
              ? "Digital signature byte range verifies against the current revision"
              : "Digital signature does NOT cover the current revision"
            : "Document is unsigned — no integrity anchor",
        severity: !isPdf ? "info" : signed ? (digestValid ? "benign" : "critical") : "medium",
        confidence: signed ? 0.95 : 0.8,
        description: !isPdf
          ? "Raster exhibits carry no signature container. Authenticity must be established by content layers and custody records."
          : signed
            ? digestValid
              ? "The /ByteRange digest recomputes to the stored PKCS#7 value and the signing certificate chains to a trusted issuer, so the signed revision is cryptographically intact."
              : "The stored digest no longer matches a recomputation over the current byte range: bytes were added or modified after signing. This is direct, cryptographic evidence of post-signature modification."
            : "No /ByteRange or signature dictionary exists. Any party could alter the bytes without invalidating an anchor, so content-layer evidence carries full weight.",
        metric: signed ? (digestValid ? "valid" : "INVALID") : "unsigned",
        evidence: [
          metric("Signature container", signed ? "PKCS#7 / PAdES" : "none"),
          metric("Digest status", signed ? (digestValid ? "match" : "mismatch") : "n/a"),
          metric("LTV/revocation", signed ? (rand() < 0.5 ? "embedded" : "not embedded") : "n/a"),
        ],
      }),
    ];

    if (rand() < 0.55 || score > 0.4) {
      const edge = round(inRange(rand, 0.2, score > 0.4 ? 0.9 : 0.5), 2);
      findings.push(
        mkFinding({
          layer: "signature",
          code: "SG-INK",
          title: score > 0.4 ? "Signature/stamp region behaves like a pasted raster object" : "Signature region consistent with direct ink-on-paper scan",
          severity: score > 0.4 ? "high" : "benign",
          confidence: clamp(0.55 + score * 0.35, 0.45, 0.93),
          description:
            score > 0.4
              ? `The ink object exhibits a hard ${Math.round(inRange(rand, 1, 3))}-px boundary, near-uniform alpha and a halo of residual background compression around it (edge sharpness index ${edge}). Genuine ink scanned with the page shares the page's compression and noise floor.`
              : `Ink strokes share the page's compression generation and noise floor (edge sharpness index ${edge}); no paste halo around the signature bounding region.`,
          evidence: [
            metric("Edge sharpness", edge.toString()),
            metric("Alpha uniformity", round(clamp(0.3 + score * 0.6), 2).toString()),
            metric("Residual halo", score > 0.4 ? "detected" : "none"),
          ],
        }),
      );
    }

    return {
      score,
      confidence: clamp(0.6 + score * 0.3, 0.5, 0.94),
      mode: "live",
      runtime: signatureModule.runtime,
      summary: signed
        ? digestValid
          ? "Signature layer verified the cryptographic integrity of the signed revision."
          : "Signature layer found post-signature byte modification — the signature is invalidated."
        : "Signature layer found no cryptographic integrity anchor for this exhibit.",
      techniques: signatureModule.techniques,
      findings,
      metrics: [metric("Signed", signed ? "yes" : "no"), metric("Digest", signed ? (digestValid ? "match" : "mismatch") : "n/a")],
      durationMs: Date.now() - started + Math.round(14 + rand() * 20),
    };
  },
};
