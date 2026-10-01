import Link from "next/link";
import type { Metadata } from "next";
import { desc } from "drizzle-orm";
import { db } from "@/db";
import { analyses } from "@/db/schema";
import { SiteFooter, SiteHeader } from "@/components/site/chrome";
import { Chip, Eyebrow } from "@/components/ui/kit";
import { fmtBytes, fmtDate, riskBand } from "@/lib/format";

export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Case register · Forgify",
  description: "Every forensic examination performed by the engine, with its verdict, risk score and report.",
};

type CaseRow = {
  id: string;
  caseCode: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  riskScore: number;
  confidence: number;
  executionMode: string;
  createdAt: Date;
};

export default async function CasesPage() {
  let rows: CaseRow[] = [];
  let stats = { total: 0, forged: 0, suspicious: 0, authentic: 0, avgRisk: 0 };
  let dbError = false;

  try {
    const result = await loadRows();
    rows = result.rows;
    stats = result.stats;
  } catch {
    dbError = true;
  }

  return (
    <>
      <SiteHeader />
      <main className="min-h-screen bg-surface">
        <section className="border-b border-hairline bg-white">
          <div className="mx-auto max-w-7xl px-5 py-10 sm:px-8">
            <Eyebrow>Case register</Eyebrow>
            <h1 className="mt-4 text-3xl leading-[1.1] font-semibold tracking-[-0.028em] text-navy-950 sm:text-[2.4rem]">
              Every examination, retained as evidence
            </h1>
            <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-graphite-500">
              Each analysis is persisted with its full JSON report, the exhibit hashes and the per-layer scores, so a
              historical case can be re-opened and re-rendered exactly as it was produced.
            </p>
          </div>
        </section>

        <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
          <div className="grid gap-px overflow-hidden rounded-2xl border border-hairline bg-hairline sm:grid-cols-2 lg:grid-cols-5">
            {[
              ["Examinations", stats.total.toString()],
              ["Likely forged (≥68)", stats.forged.toString()],
              ["Suspicious (45–67)", stats.suspicious.toString()],
              ["Low risk / authentic", stats.authentic.toString()],
              ["Mean risk", `${stats.avgRisk}/100`],
            ].map(([label, value]) => (
              <div key={label} className="bg-white px-5 py-4">
                <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">{label}</p>
                <p className="tabular mt-1.5 font-mono text-[22px] leading-none font-semibold text-navy-950">{value}</p>
              </div>
            ))}
          </div>

          {dbError ? (
            <p className="mt-6 rounded-xl border border-dashed border-hairline px-5 py-8 text-center text-[13px] text-graphite-500">
              The case store is unavailable. Run <span className="font-mono text-[12px]">npx drizzle-kit push</span> to
              create the schema.
            </p>
          ) : rows.length === 0 ? (
            <div className="mt-6 rounded-2xl border border-dashed border-navy-200 bg-white px-6 py-16 text-center">
              <p className="text-[15px] font-medium text-navy-950">No examinations yet</p>
              <p className="mx-auto mt-2 max-w-md text-[13px] leading-relaxed text-graphite-500">
                The register fills up as exhibits are analysed. Run one from the workbench — sample exhibits are
                provided, no account required.
              </p>
              <Link
                href="/analyze"
                className="mt-6 inline-flex items-center gap-2 rounded-lg bg-navy-950 px-4 py-2.5 text-[13px] font-medium text-white transition-colors hover:bg-navy-900"
              >
                Open the workbench
                <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                  <path d="M3 8h10M9 4l4 4-4 4" />
                </svg>
              </Link>
            </div>
          ) : (
            <div className="mt-6 overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
              <div className="overflow-x-auto">
                <table className="w-full min-w-[900px] text-left">
                  <thead>
                    <tr className="border-b border-hairline bg-navy-50/60">
                      {["Case", "Exhibit", "Verdict", "Risk", "Confidence", "Mode", "Hash", "Analysed"].map((h) => (
                        <th key={h} className="px-5 py-3 font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((row) => {
                      const band = riskBand(row.riskScore);
                      return (
                        <tr key={row.id} className="border-b border-hairline transition-colors last:border-0 hover:bg-navy-50/40">
                          <td className="px-5 py-3.5">
                            <Link href={`/cases/${row.id}`} className="font-mono text-[12px] text-electric-600 hover:underline">
                              {row.caseCode}
                            </Link>
                          </td>
                          <td className="max-w-[240px] px-5 py-3.5">
                            <p className="truncate text-[13px] font-medium text-navy-950">{row.filename}</p>
                            <p className="font-mono text-[10px] text-graphite-500">
                              {row.mimeType} · {fmtBytes(row.sizeBytes)}
                            </p>
                          </td>
                          <td className="px-5 py-3.5">
                            <span
                              className="rounded px-2 py-1 font-mono text-[9.5px] tracking-[0.1em] uppercase"
                              style={{ background: band.bg, color: band.color, border: `1px solid ${band.border}` }}
                            >
                              {band.label}
                            </span>
                          </td>
                          <td className="tabular px-5 py-3.5">
                            <span className="font-mono text-[13px] font-semibold" style={{ color: band.color }}>
                              {row.riskScore}
                            </span>
                            <span className="font-mono text-[10px] text-graphite-500">/100</span>
                          </td>
                          <td className="tabular px-5 py-3.5 font-mono text-[12px] text-graphite-700">{row.confidence}%</td>
                          <td className="px-5 py-3.5">
                            <Chip tone={row.executionMode === "live" ? "live" : "neutral"}>{row.executionMode}</Chip>
                          </td>
                          <td className="px-5 py-3.5 font-mono text-[11px] text-graphite-500">{row.sha256.slice(0, 12)}…</td>
                          <td className="px-5 py-3.5 font-mono text-[11px] text-graphite-500">{fmtDate(row.createdAt)}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          <p className="mt-4 font-mono text-[10.5px] text-graphite-500">
            API · <span className="text-navy-900">GET /api/analyses</span> · filter with{" "}
            <span className="text-navy-900">?verdict=&amp;q=&amp;limit=&amp;offset=</span>
          </p>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}

async function loadRows(): Promise<{
  rows: CaseRow[];
  stats: { total: number; forged: number; suspicious: number; authentic: number; avgRisk: number };
}> {
  const rows = await db
    .select({
      id: analyses.id,
      caseCode: analyses.caseCode,
      filename: analyses.filename,
      mimeType: analyses.mimeType,
      sizeBytes: analyses.sizeBytes,
      sha256: analyses.sha256,
      riskScore: analyses.riskScore,
      confidence: analyses.confidence,
      executionMode: analyses.executionMode,
      createdAt: analyses.createdAt,
    })
    .from(analyses)
    .orderBy(desc(analyses.createdAt))
    .limit(50);

  const total = rows.length;
  const forged = rows.filter((r) => r.riskScore >= 68).length;
  const suspicious = rows.filter((r) => r.riskScore >= 45 && r.riskScore < 68).length;
  const authentic = total - forged - suspicious;
  const avgRisk = total ? Math.round(rows.reduce((a, r) => a + r.riskScore, 0) / total) : 0;

  return { rows, stats: { total, forged, suspicious, authentic, avgRisk } };
}
