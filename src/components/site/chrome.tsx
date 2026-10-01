"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

const NAV = [
  { href: "/#why", label: "The problem" },
  { href: "/#layers", label: "11 layers" },
  { href: "/#pipeline", label: "How it works" },
  { href: "/#fusion", label: "Evidence fusion" },
  { href: "/#report", label: "Report" },
  { href: "/#research", label: "Methodology" },
];

export function SiteHeader() {
  const [scrolled, setScrolled] = useState(false);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`sticky top-0 z-50 border-b transition-all duration-300 ${
        scrolled ? "border-hairline bg-white/95 backdrop-blur-md" : "border-transparent bg-white"
      }`}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-5 sm:px-8">
        <Link href="/" className="group flex items-center gap-3">
          <span className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-navy-950">
            <svg viewBox="0 0 24 24" className="h-4.5 w-4.5" fill="none" stroke="#5c85ff" strokeWidth="1.6">
              <path d="M12 2.5 4.5 5.5v6c0 4.6 3.1 8.4 7.5 10 4.4-1.6 7.5-5.4 7.5-10v-6L12 2.5Z" />
              <path d="M12 8v8M8.5 12h7" stroke="#06b6d4" />
            </svg>
          </span>
          <span className="leading-none">
            <span className="block text-[15px] font-semibold tracking-[-0.01em] text-navy-950">Forgify</span>
            <span className="mt-1 block font-mono text-[9.5px] tracking-[0.2em] text-graphite-500 uppercase">
              Digital forensics engine
            </span>
          </span>
        </Link>

        <nav className="hidden items-center gap-7 lg:flex">
          {NAV.map((item) => (
            <a
              key={item.href}
              href={item.href}
              className="relative text-[13.5px] font-medium text-graphite-700 transition-colors hover:text-navy-950 after:absolute after:-bottom-1.5 after:left-0 after:h-px after:w-0 after:bg-electric-600 after:transition-all after:duration-300 hover:after:w-full"
            >
              {item.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2.5">
          <Link
            href="/cases"
            className="hidden rounded-lg border border-hairline px-3.5 py-2 text-[13px] font-medium text-graphite-700 transition-colors hover:border-navy-300 hover:text-navy-950 sm:block"
          >
            Case register
          </Link>
          <Link
            href="/analyze"
            className="group inline-flex items-center gap-2 rounded-lg bg-navy-950 px-4 py-2 text-[13px] font-medium text-white transition-all hover:bg-navy-900"
          >
            Analyze a document
            <svg viewBox="0 0 16 16" className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" fill="none" stroke="currentColor" strokeWidth="1.7">
              <path d="M3 8h10M9 4l4 4-4 4" />
            </svg>
          </Link>
          <button
            type="button"
            aria-label="Toggle navigation"
            onClick={() => setOpen((v) => !v)}
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-hairline text-navy-900 lg:hidden"
          >
            <svg viewBox="0 0 20 20" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.6">
              {open ? <path d="M5 5l10 10M15 5L5 15" /> : <path d="M3 6h14M3 10h14M3 14h14" />}
            </svg>
          </button>
        </div>
      </div>

      {open ? (
        <div className="border-t border-hairline bg-white px-5 pb-4 lg:hidden">
          <nav className="grid gap-1 pt-3">
            {NAV.map((item) => (
              <a key={item.href} href={item.href} onClick={() => setOpen(false)} className="rounded-lg px-3 py-2.5 text-sm text-graphite-700 hover:bg-navy-50">
                {item.label}
              </a>
            ))}
            <Link href="/cases" className="rounded-lg px-3 py-2.5 text-sm text-graphite-700 hover:bg-navy-50">
              Case register
            </Link>
          </nav>
        </div>
      ) : null}
    </header>
  );
}

export function SiteFooter() {
  const layers = [
    "Pixel integrity",
    "Compression history",
    "Metadata forensics",
    "Provenance",
    "OCR & glyphs",
    "Layout geometry",
    "Copy-move & splice",
    "Signature & seal",
    "QR / barcode",
    "Semantic consistency",
    "Generative-AI detection",
  ];
  return (
    <footer className="border-t border-hairline bg-navy-950 text-navy-200">
      <div className="mx-auto max-w-7xl px-5 py-16 sm:px-8">
        <div className="grid gap-12 lg:grid-cols-[1.4fr_1fr_1fr]">
          <div>
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-navy-900">
                <svg viewBox="0 0 24 24" className="h-4.5 w-4.5" fill="none" stroke="#5c85ff" strokeWidth="1.6">
                  <path d="M12 2.5 4.5 5.5v6c0 4.6 3.1 8.4 7.5 10 4.4-1.6 7.5-5.4 7.5-10v-6L12 2.5Z" />
                  <path d="M12 8v8M8.5 12h7" stroke="#06b6d4" />
                </svg>
              </span>
              <span className="text-[15px] font-semibold tracking-[-0.01em] text-white">Forgify</span>
            </div>
            <p className="mt-5 max-w-sm text-[13.5px] leading-relaxed text-navy-300">
              Multi-layer AI-assisted digital forensics system for detecting image, document, metadata and
              generative-AI-based forgeries. Built as a final-year research project: modular detectors,
              explainable evidence fusion and a reproducible analysis pipeline.
            </p>
            <div className="mt-6 flex flex-wrap gap-2">
              <span className="rounded-md border border-navy-800 px-2.5 py-1 font-mono text-[10px] tracking-[0.12em] text-navy-300 uppercase">
                Engine v2.4.0
              </span>
              <span className="rounded-md border border-navy-800 px-2.5 py-1 font-mono text-[10px] tracking-[0.12em] text-navy-300 uppercase">
                11 detector layers
              </span>
              <span className="rounded-md border border-navy-800 px-2.5 py-1 font-mono text-[10px] tracking-[0.12em] text-navy-300 uppercase">
                Open API
              </span>
            </div>
          </div>

          <div>
            <h3 className="font-mono text-[10.5px] tracking-[0.18em] text-navy-400 uppercase">Detector stack</h3>
            <ul className="mt-4 grid gap-2 text-[13px] text-navy-300">
              {layers.map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
          </div>

          <div>
            <h3 className="font-mono text-[10.5px] tracking-[0.18em] text-navy-400 uppercase">Platform</h3>
            <ul className="mt-4 grid gap-2.5 text-[13px]">
              <li><Link className="text-navy-300 transition-colors hover:text-white" href="/analyze">Analysis workbench</Link></li>
              <li><Link className="text-navy-300 transition-colors hover:text-white" href="/cases">Case register</Link></li>
              <li><a className="text-navy-300 transition-colors hover:text-white" href="/api/layers">Engine contract (JSON)</a></li>
              <li><Link className="text-navy-300 transition-colors hover:text-white" href="/#research">Dataset &amp; methodology</Link></li>
              <li><Link className="text-navy-300 transition-colors hover:text-white" href="/#limitations">Security &amp; limitations</Link></li>
            </ul>
            <h3 className="mt-8 font-mono text-[10.5px] tracking-[0.18em] text-navy-400 uppercase">Runtime</h3>
            <p className="mt-3 text-[13px] leading-relaxed text-navy-300">
              Next.js · TypeScript · PostgreSQL (Drizzle) · modular inference adapters with a FastAPI/OpenCV
              bridge for trained models.
            </p>
          </div>
        </div>

        <div className="mt-14 flex flex-col gap-3 border-t border-navy-900 pt-6 text-[12px] text-navy-400 sm:flex-row sm:items-center sm:justify-between">
          <p>© {new Date().getFullYear()} Forgify · Final-year project build. Evidence outputs are decision support, not legal certification.</p>
          <p className="font-mono tracking-[0.1em] uppercase">Investigate every layer · Detect every forgery</p>
        </div>
      </div>
    </footer>
  );
}
