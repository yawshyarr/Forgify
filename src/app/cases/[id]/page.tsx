import Link from "next/link";
import { notFound } from "next/navigation";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { analyses } from "@/db/schema";
import { SiteFooter, SiteHeader } from "@/components/site/chrome";
import { ReportDashboard } from "@/components/analyze/ReportDashboard";
import { Eyebrow } from "@/components/ui/kit";
import type { AnalysisReport } from "@/lib/forensics/types";

export const dynamic = "force-dynamic";

export default async function CaseDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) notFound();

  const [row] = await db.select().from(analyses).where(eq(analyses.id, id)).limit(1);
  if (!row) notFound();

  const report = row.report as AnalysisReport;
  const enriched: AnalysisReport = { ...report, id: row.id, caseCode: row.caseCode };

  return (
    <>
      <SiteHeader />
      <main className="min-h-screen bg-surface">
        <section className="border-b border-hairline bg-white">
          <div className="mx-auto flex max-w-7xl flex-wrap items-end justify-between gap-4 px-5 py-8 sm:px-8">
            <div>
              <Eyebrow>Archived case</Eyebrow>
              <h1 className="mt-3 text-2xl font-semibold tracking-[-0.025em] text-navy-950 sm:text-[1.9rem]">
                {row.caseCode}
              </h1>
              <p className="mt-2 max-w-2xl text-[13.5px] leading-relaxed text-graphite-500">
                Reopened from the case store. The report below is the exact JSON produced at analysis time, including
                the engine version, per-layer runtimes and the fusion trace.
              </p>
            </div>
            <div className="flex items-center gap-2.5">
              <Link
                href="/cases"
                className="rounded-lg border border-hairline px-3.5 py-2 text-[13px] font-medium text-graphite-700 transition-colors hover:border-navy-300 hover:text-navy-950"
              >
                ← Case register
              </Link>
              <Link
                href="/analyze"
                className="rounded-lg bg-navy-950 px-3.5 py-2 text-[13px] font-medium text-white transition-colors hover:bg-navy-900"
              >
                New examination
              </Link>
            </div>
          </div>
        </section>

        <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
          <ReportDashboard report={enriched} assetUrl={row.assetDataUrl} readonly />
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
