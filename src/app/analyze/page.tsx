import Link from "next/link";
import type { Metadata } from "next";
import { SiteFooter, SiteHeader } from "@/components/site/chrome";
import { Workbench } from "@/components/analyze/Workbench";
import { Chip, Eyebrow, LiveDot } from "@/components/ui/kit";
import { LAYERS } from "@/lib/forensics/registry";

export const metadata: Metadata = {
  title: "Analysis workbench · Forgify",
  description: "Upload a PDF or image and run the eleven-layer forensic analysis pipeline.",
};

export default function AnalyzePage() {
  return (
    <>
      <SiteHeader />
      <main className="min-h-screen bg-surface">
        <section className="border-b border-hairline bg-white">
          <div className="mx-auto max-w-7xl px-5 py-10 sm:px-8">
            <div className="flex flex-wrap items-start justify-between gap-6">
              <div>
                <Eyebrow>Analysis workbench</Eyebrow>
                <h1 className="mt-4 text-3xl leading-[1.1] font-semibold tracking-[-0.028em] text-navy-950 sm:text-[2.4rem]">
                  Examine an exhibit
                </h1>
                <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-graphite-500">
                  One request runs the full eight-stage pipeline across all eleven forensic layers, then returns a
                  structured report with the risk score, confidence, localised regions and the evidence behind every
                  finding. Results are persisted to the case register.
                </p>
              </div>
              <div className="flex flex-col items-start gap-3">
                <div className="flex flex-wrap gap-2">
                  <Chip tone="navy">
                    <LiveDot color="#06b6d4" />
                    engine v2.4.0
                  </Chip>
                  <Chip tone="outline">{LAYERS.length} layers</Chip>
                  <Chip tone="outline">POST /api/analyze</Chip>
                </div>
                <Link
                  href="/cases"
                  className="text-[13px] font-medium text-electric-600 underline decoration-electric-200 underline-offset-4 transition-colors hover:decoration-electric-500"
                >
                  View the case register →
                </Link>
              </div>
            </div>
          </div>
        </section>

        <div className="mx-auto max-w-7xl px-5 py-8 sm:px-8">
          <Workbench />

          <section className="mt-8 grid gap-px overflow-hidden rounded-2xl border border-hairline bg-hairline sm:grid-cols-3">
            {[
              {
                t: "Deterministic by construction",
                d: "Every modelled adapter is seeded from the exhibit's SHA-256. Re-analysing the same bytes reproduces the same report byte-for-byte — which is what makes the output auditable.",
              },
              {
                t: "Live where it can be",
                d: "Hashing, container parsing, EXIF/XMP presence, PNG CRC validation, PDF revision counting and quantisation quality are read from the real bytes, not simulated.",
              },
              {
                t: "Adapter-ready for real models",
                d: "Layers that need trained models run through a documented interface. Point FORENSICS_ENGINE_URL at the FastAPI/OpenCV worker and the pipeline switches over without UI changes.",
              },
            ].map((c) => (
              <div key={c.t} className="bg-white p-5">
                <h3 className="text-[13.5px] font-semibold tracking-[-0.01em] text-navy-950">{c.t}</h3>
                <p className="mt-2 text-[12.5px] leading-relaxed text-graphite-500">{c.d}</p>
              </div>
            ))}
          </section>
        </div>
      </main>
      <SiteFooter />
    </>
  );
}
