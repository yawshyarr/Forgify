import { NextResponse } from "next/server";
import { db } from "@/db";
import { analyses, findings as findingsTable, regions as regionsTable } from "@/db/schema";
import { analyzeEvidence } from "@/lib/forensics/engine";
import { analyzeRemote, bridgeUrl } from "@/lib/forensics/bridge";
import { VERDICT_LABEL } from "@/lib/forensics/fusion";
import type { AnalysisReport } from "@/lib/forensics/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

const MAX_BYTES = 20 * 1024 * 1024;

const SUPPORTED = [
  "image/jpeg",
  "image/jpg",
  "image/png",
  "image/webp",
  "image/tiff",
  "image/bmp",
  "image/heic",
  "application/pdf",
];

function bad(message: string, status = 400, extra: Record<string, unknown> = {}) {
  return NextResponse.json({ ok: false, error: message, ...extra }, { status });
}

export async function POST(request: Request) {
  try {
    return await handle(request);
  } catch (error) {
    console.error("[analyze] pipeline failure", error);
    return NextResponse.json(
      {
        ok: false,
        error: "The forensic pipeline failed on this exhibit.",
        detail: error instanceof Error ? error.message : String(error),
      },
      { status: 500 },
    );
  }
}

async function handle(request: Request) {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return bad("Expected a multipart/form-data body with a `file` field.");
  }

  const file = form.get("file");
  if (!file || typeof file === "string") return bad("No evidence file was supplied as the `file` field.");

  const refEntry = form.get("reference");
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length === 0) return bad("The uploaded file is empty.");
  if (bytes.length > MAX_BYTES) return bad("File exceeds the 20 MB analysis limit.", 413);

  const mimeType = file.type || "application/octet-stream";
  const name = file.name || "evidence.bin";
  const isLikelySupported = SUPPORTED.some((t) => mimeType.includes(t)) || /\.(pdf|png|jpe?g|webp|tiff?|bmp|heic)$/i.test(name);
  if (!isLikelySupported) {
    return bad(
      `Unsupported evidence type "${mimeType || name}". Accepted: PDF, JPEG, PNG, WebP, TIFF, BMP, HEIC.`,
      415,
      { supported: SUPPORTED },
    );
  }

  let reference: { bytes: Uint8Array; name: string; mimeType: string } | null = null;
  if (refEntry && typeof refEntry !== "string") {
    const refBytes = new Uint8Array(await refEntry.arrayBuffer());
    if (refBytes.length > 0 && refBytes.length <= MAX_BYTES) {
      reference = { bytes: refBytes, name: refEntry.name || "reference.bin", mimeType: refEntry.type || "application/octet-stream" };
    }
  }

  const remote = bridgeUrl();
  let report: AnalysisReport | null = null;
  let backend: "typescript-reference" | "python-fastapi" = "typescript-reference";

  if (remote) {
    const forwarded = await analyzeRemote({ bytes, name, mimeType, reference }, remote);
    if (forwarded) {
      report = forwarded;
      backend = "python-fastapi";
    }
  }
  if (!report) {
    // The reference engine is deterministic and useful for UI development, but
    // it is not evidence-grade inference. Never let it silently produce a
    // report that an examiner could mistake for a live forensic result.
    if (process.env.FORENSICS_ALLOW_REFERENCE_ENGINE !== "true") {
      return bad(
        remote
          ? "The live forensic worker is unavailable. No result was issued because the evidence-grade backend could not be reached."
          : "The live forensic worker is not configured. Set FORENSICS_ENGINE_URL and start the Python worker before analysing evidence.",
        503,
        { code: "FORENSICS_ENGINE_UNAVAILABLE", backend: "python-fastapi" },
      );
    }
    report = analyzeEvidence({ bytes, name, mimeType, reference });
    report.engine.backend = backend;
    report.limitations = [
      ...report.limitations,
      "This report was produced by the explicitly enabled TypeScript reference engine for demonstration/testing only. It is not evidence-grade and must not be used to certify authenticity or forgery.",
    ];
  }

  /* ------------------------------- persistence ------------------------------ */
  const isImage = report.file.kind !== "pdf" && bytes.length <= 4_500_000;
  const assetDataUrl = isImage ? `data:${report.container.detectedType};base64,${Buffer.from(bytes).toString("base64")}` : null;

  let persistedId: string | null = null;
  try {
    const [row] = await db
      .insert(analyses)
      .values({
        caseCode: report.caseCode,
        filename: report.file.name,
        mimeType: report.file.mimeType,
        sizeBytes: report.file.sizeBytes,
        sha256: report.hashes.sha256,
        md5: report.hashes.md5,
        sha1: report.hashes.sha1,
        verdict: report.verdict.label,
        riskScore: report.verdict.riskScore,
        confidence: Math.round(report.verdict.confidence * 100),
        recommendation: report.verdict.recommendation,
        layerScores: report.layers.reduce<Record<string, number>>((acc, l) => {
          acc[l.layer] = l.score;
          return acc;
        }, {}),
        engine: `${report.engine.name} v${report.engine.version}`,
        executionMode: report.layers.every((l) => l.mode === "live") ? "live" : "modelled",
        durationMs: report.durationMs,
        referenceMode: report.reference.mode,
        assetDataUrl,
        report,
      })
      .returning({ id: analyses.id });
    persistedId = row?.id ?? null;

    if (persistedId) {
      const flat = report.findings.slice(0, 120);
      if (flat.length) {
        await db.insert(findingsTable).values(
          flat.map((f) => ({
            analysisId: persistedId!,
            layer: f.layer,
            code: f.code,
            title: f.title,
            severity: f.severity,
            confidence: f.confidence,
            description: f.description,
            evidence: f.evidence,
            region: f.region ?? null,
          })),
        );
      }
      if (report.regions.length) {
        await db.insert(regionsTable).values(
          report.regions.map((r) => ({
            analysisId: persistedId!,
            label: r.label,
            layer: r.layer,
            score: r.score,
            confidence: r.confidence,
            x: r.x,
            y: r.y,
            width: r.width,
            height: r.height,
            notes: r.notes,
          })),
        );
      }
    }
  } catch (error) {
    console.error("[analyze] persistence failed", error);
  }

  const savedReport: AnalysisReport = { ...report, id: persistedId ?? "" };

  return NextResponse.json({
    ok: true,
    analysisId: persistedId,
    backend,
    verdictLabel: VERDICT_LABEL[report.verdict.label],
    report: savedReport,
  });
}
