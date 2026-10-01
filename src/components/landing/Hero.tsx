import Link from "next/link";
import { ForensicDocument } from "@/components/visuals/ForensicDocument";
import { Chip, LiveDot } from "@/components/ui/kit";

const EVIDENCE_TYPES = [
  "pixel",
  "metadata",
  "provenance",
  "OCR",
  "layout",
  "compression",
  "copy-move",
  "signature",
  "QR/barcode",
  "semantic consistency",
  "AI-generated content",
];

export function Hero() {
  return (
    <section className="relative overflow-hidden border-b border-hairline">
      <div className="hairline-grid absolute inset-0 opacity-70" />
      <div className="absolute inset-x-0 top-0 h-px bg-navy-100" />
      <div className="relative mx-auto max-w-7xl px-5 pt-16 pb-24 sm:px-8 sm:pt-20 lg:pt-24">
        <div className="grid items-start gap-14 lg:grid-cols-[1.02fr_1.1fr] lg:gap-12">
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <Chip tone="navy">
                <LiveDot color="#06b6d4" />
                Forensic engine v2.4.0
              </Chip>
              <Chip tone="outline">Final-year research project</Chip>
            </div>

            <h1 className="mt-7 text-[2.6rem] leading-[1.04] font-semibold tracking-[-0.032em] text-navy-950 text-balance sm:text-[3.35rem] lg:text-[3.7rem]">
              Investigate Every Layer.
              <span className="block text-electric-600">Detect Every Forgery.</span>
            </h1>

            <p className="mt-6 max-w-xl text-[16px] leading-relaxed text-graphite-500">
              Forgify examines a document the way an examiner would — layer by layer. Each submission is
              dissected for{" "}
              <span className="font-medium text-navy-900">{EVIDENCE_TYPES.slice(0, 5).join(", ")}</span>,{" "}
              <span className="font-medium text-navy-900">{EVIDENCE_TYPES.slice(5, 9).join(", ")}</span> and{" "}
              <span className="font-medium text-navy-900">{EVIDENCE_TYPES.slice(9).join(", ")}</span> evidence, then
              fused into one calibrated risk score with an explanation you can defend in a viva — or in court.
            </p>

            <div className="mt-9 flex flex-wrap items-center gap-3">
              <Link
                href="/analyze"
                className="group inline-flex items-center gap-2.5 rounded-lg bg-navy-950 px-5 py-3 text-[14px] font-medium text-white shadow-[var(--shadow-card)] transition-all duration-300 hover:bg-navy-900 hover:shadow-[var(--shadow-lift)]"
              >
                Analyze a Document
                <svg viewBox="0 0 16 16" className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                  <path d="M3 8h10M9 4l4 4-4 4" />
                </svg>
              </Link>
              <a
                href="#pipeline"
                className="group inline-flex items-center gap-2.5 rounded-lg border border-navy-200 bg-white px-5 py-3 text-[14px] font-medium text-navy-900 transition-all duration-300 hover:border-electric-400 hover:text-electric-600"
              >
                Explore How It Works
                <svg viewBox="0 0 16 16" className="h-4 w-4 transition-transform duration-300 group-hover:translate-y-0.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                  <path d="M8 3v10M4 9l4 4 4-4" />
                </svg>
              </a>
            </div>

            <dl className="mt-12 grid max-w-lg grid-cols-2 gap-x-8 gap-y-6 sm:grid-cols-4">
              {[
                ["11", "detector layers"],
                ["8", "pipeline stages"],
                ["JSON", "structured report"],
                ["100%", "reproducible per file"],
              ].map(([value, label]) => (
                <div key={label}>
                  <dt className="tabular font-mono text-[22px] leading-none font-semibold tracking-[-0.02em] text-navy-950">
                    {value}
                  </dt>
                  <dd className="mt-2 text-[11.5px] leading-snug text-graphite-500">{label}</dd>
                </div>
              ))}
            </dl>

            <div className="mt-10 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-hairline pt-5 font-mono text-[10.5px] tracking-[0.1em] text-graphite-500 uppercase">
              <span>POST /api/analyze</span>
              <span className="text-navy-200">|</span>
              <span>multipart evidence intake</span>
              <span className="text-navy-200">|</span>
              <span>SHA-256 recorded pre-processing</span>
            </div>
          </div>

          <div className="relative lg:pl-6 lg:pt-4">
            <ForensicDocument />
          </div>
        </div>
      </div>
    </section>
  );
}
