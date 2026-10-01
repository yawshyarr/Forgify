import { NextResponse } from "next/server";
import { and, desc, eq, ilike, sql } from "drizzle-orm";
import { db } from "@/db";
import { analyses } from "@/db/schema";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const limit = Math.min(60, Math.max(1, Number(url.searchParams.get("limit") ?? 20)));
  const offset = Math.max(0, Number(url.searchParams.get("offset") ?? 0));
  const verdict = url.searchParams.get("verdict");
  const q = url.searchParams.get("q");

  const filters = [];
  if (verdict && verdict !== "all") filters.push(eq(analyses.verdict, verdict));
  if (q) filters.push(ilike(analyses.filename, `%${q}%`));
  const where = filters.length ? and(...filters) : undefined;

  try {
    const rows = await db
      .select({
        id: analyses.id,
        caseCode: analyses.caseCode,
        filename: analyses.filename,
        mimeType: analyses.mimeType,
        sizeBytes: analyses.sizeBytes,
        sha256: analyses.sha256,
        verdict: analyses.verdict,
        riskScore: analyses.riskScore,
        confidence: analyses.confidence,
        engine: analyses.engine,
        executionMode: analyses.executionMode,
        referenceMode: analyses.referenceMode,
        durationMs: analyses.durationMs,
        createdAt: analyses.createdAt,
        layerScores: analyses.layerScores,
      })
      .from(analyses)
      .where(where)
      .orderBy(desc(analyses.createdAt))
      .limit(limit)
      .offset(offset);

    const [stats] = await db
      .select({
        total: sql<number>`count(*)::int`,
        forged: sql<number>`count(*) filter (where ${analyses.riskScore} >= 68)::int`,
        suspicious: sql<number>`count(*) filter (where ${analyses.riskScore} >= 45 and ${analyses.riskScore} < 68)::int`,
        authentic: sql<number>`count(*) filter (where ${analyses.riskScore} < 45)::int`,
        avgRisk: sql<number>`coalesce(round(avg(${analyses.riskScore}))::int, 0)`,
        avgDuration: sql<number>`coalesce(round(avg(${analyses.durationMs}))::int, 0)`,
      })
      .from(analyses);

    return NextResponse.json({ ok: true, rows, stats, limit, offset });
  } catch (error) {
    console.error("[analyses] query failed", error);
    return NextResponse.json({ ok: false, rows: [], stats: null, error: "Case history unavailable" }, { status: 500 });
  }
}
