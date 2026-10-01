"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { ReportDashboard } from "@/components/analyze/ReportDashboard";
import { Chip } from "@/components/ui/kit";
import { fmtBytes } from "@/lib/format";
import type { AnalysisReport } from "@/lib/forensics/types";

const STAGES = [
  "Intake & multipart read",
  "Magic-byte validation · hashing",
  "Container & metadata extraction",
  "11-layer forensic analysis",
  "Cross-layer corroboration",
  "Evidence fusion",
  "Risk calibration",
  "Explainable report build",
];

const SAMPLES = [
  { label: "Tampered invoice (JPG)", href: "/samples/tampered-invoice.jpg", note: "Edited totals · pasted stamp" },
  { label: "Certificate scan (JPG)", href: "/samples/certificate.jpg", note: "Clean reference exhibit" },
];

type Phase = "idle" | "working" | "done" | "error";

export function Workbench({ initialReport, initialAsset }: { initialReport?: AnalysisReport | null; initialAsset?: string | null }) {
  const [file, setFile] = useState<File | null>(null);
  const [reference, setReference] = useState<File | null>(null);
  const [phase, setPhase] = useState<Phase>(initialReport ? "done" : "idle");
  const [stage, setStage] = useState(0);
  const [report, setReport] = useState<AnalysisReport | null>(initialReport ?? null);
  const [assetUrl, setAssetUrl] = useState<string | null>(initialAsset ?? null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const refInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (phase !== "working") return;
    const timer = setInterval(() => setStage((s) => Math.min(STAGES.length - 1, s + 1)), 420);
    return () => clearInterval(timer);
  }, [phase]);

  const analyze = useCallback(async (target: File, refFile: File | null) => {
    setStage(0);
    setPhase("working");
    setError(null);
    setReport(null);
    try {
      const body = new FormData();
      body.append("file", target);
      if (refFile) body.append("reference", refFile);
      const res = await fetch("/api/analyze", { method: "POST", body });
      const json = (await res.json()) as { ok: boolean; report?: AnalysisReport; error?: string };
      if (!res.ok || !json.ok || !json.report) {
        setError(json.error ?? "Analysis failed.");
        setPhase("error");
        return;
      }
      setReport(json.report);
      setAssetUrl(
        target.type.startsWith("image/") && target.size < 8_000_000 ? URL.createObjectURL(target) : null,
      );
      setPhase("done");
      requestAnimationFrame(() => {
        document.getElementById("analysis-output")?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    } catch {
      setError("Network error while contacting the forensic engine.");
      setPhase("error");
    }
  }, []);

  const loadSample = useCallback(
    async (href: string, name: string) => {
      try {
        const res = await fetch(href);
        const blob = await res.blob();
        const sample = new File([blob], name, { type: blob.type || "image/jpeg" });
        setFile(sample);
        setReference(null);
        await analyze(sample, null);
      } catch {
        setError("Could not load the sample exhibit.");
        setPhase("error");
      }
    },
    [analyze],
  );

  const reset = () => {
    setFile(null);
    setReference(null);
    setReport(null);
    setAssetUrl(null);
    setError(null);
    setPhase("idle");
    if (inputRef.current) inputRef.current.value = "";
    if (refInputRef.current) refInputRef.current.value = "";
  };

  return (
    <div className="grid gap-6">
      <section className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-5 py-4">
          <div>
            <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-navy-950">Evidence intake</h2>
            <p className="mt-1 text-[12.5px] text-graphite-500">
              PDF, JPEG, PNG, WebP, TIFF or BMP up to 20 MB. Optional reference exhibit enables reference-based mode.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Chip tone="outline">read-only processing</Chip>
            <Chip tone="live">SHA-256 at intake</Chip>
          </div>
        </div>

        <div className="grid gap-5 p-5 lg:grid-cols-[1.35fr_0.65fr]">
          <div>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                const dropped = e.dataTransfer.files?.[0];
                if (dropped) setFile(dropped);
              }}
              onClick={() => inputRef.current?.click()}
              className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition-all duration-200 ${
                dragging ? "border-electric-500 bg-electric-50" : "border-navy-200 bg-surface/70 hover:border-electric-400 hover:bg-electric-50/50"
              }`}
            >
              <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-hairline bg-white">
                <svg viewBox="0 0 20 20" className="h-5 w-5 text-electric-600" fill="none" stroke="currentColor" strokeWidth="1.6">
                  <path d="M10 13V3M6 7l4-4 4 4M3 15v2h14v-2" />
                </svg>
              </span>
              <p className="mt-4 text-[14px] font-medium text-navy-950">
                {file ? file.name : "Drop an exhibit here, or click to browse"}
              </p>
              <p className="mt-1.5 font-mono text-[11px] text-graphite-500">
                {file
                  ? `${fmtBytes(file.size)} · ${file.type || "unknown type"}`
                  : "The engine reads the byte structure — the extension is never trusted"}
              </p>
              <input
                ref={inputRef}
                type="file"
                accept=".pdf,image/*"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </div>

            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              {SAMPLES.map((s) => (
                <button
                  key={s.href}
                  type="button"
                  onClick={() => loadSample(s.href, s.href.split("/").pop() ?? "sample.jpg")}
                  className="group flex items-center justify-between gap-3 rounded-lg border border-hairline bg-white px-3.5 py-2.5 text-left transition-all hover:border-electric-400"
                >
                  <span>
                    <span className="block text-[12.5px] font-medium text-navy-950">{s.label}</span>
                    <span className="mt-0.5 block font-mono text-[10px] text-graphite-500">{s.note}</span>
                  </span>
                  <svg viewBox="0 0 16 16" className="h-3.5 w-3.5 shrink-0 text-graphite-500 transition-transform group-hover:translate-x-0.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                    <path d="M3 8h10M9 4l4 4-4 4" />
                  </svg>
                </button>
              ))}
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-2 rounded-lg border border-hairline bg-surface/70 px-3.5 py-2.5">
              <button
                type="button"
                onClick={() => refInputRef.current?.click()}
                className="inline-flex items-center gap-2 text-[12.5px] font-medium text-navy-900 transition-colors hover:text-electric-600"
              >
                <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.6">
                  <path d="M2 4h8v8H2zM10 6h4v6h-4" />
                </svg>
                {reference ? `Reference: ${reference.name}` : "Add a trusted reference exhibit (optional)"}
              </button>
              {reference ? (
                <button type="button" onClick={() => setReference(null)} className="ml-auto font-mono text-[10px] tracking-[0.1em] text-[#b42318] uppercase">
                  remove
                </button>
              ) : (
                <span className="ml-auto font-mono text-[10px] tracking-[0.1em] text-graphite-500 uppercase">enables delta mode</span>
              )}
              <input
                ref={refInputRef}
                type="file"
                accept=".pdf,image/*"
                className="hidden"
                onChange={(e) => setReference(e.target.files?.[0] ?? null)}
              />
            </div>
          </div>

          <div className="flex flex-col justify-between rounded-xl border border-hairline bg-navy-950 p-5">
            <div>
              <p className="font-mono text-[10px] tracking-[0.16em] text-[#5c85ff] uppercase">Pipeline</p>
              <ol className="mt-3.5 grid gap-1.5">
                {STAGES.map((s, i) => {
                  const active = phase === "working" && i === stage;
                  const done = phase === "done" || (phase === "working" && i < stage);
                  return (
                    <li key={s} className="flex items-center gap-2.5">
                      <span
                        className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full border transition-colors"
                        style={{
                          borderColor: done ? "#0f9b8e" : active ? "#5c85ff" : "#1d3a63",
                          background: done ? "#0f9b8e" : active ? "#5c85ff" : "transparent",
                        }}
                      >
                        {done ? (
                          <svg viewBox="0 0 12 12" className="h-2.5 w-2.5" fill="none" stroke="#ffffff" strokeWidth="2">
                            <path d="M2.5 6l2.5 2.5L9.5 3.5" />
                          </svg>
                        ) : null}
                      </span>
                      <span
                        className="text-[11.5px] leading-snug transition-colors"
                        style={{ color: done ? "#c8d6ea" : active ? "#ffffff" : "#6288b8" }}
                      >
                        {s}
                      </span>
                    </li>
                  );
                })}
              </ol>
            </div>

            <div className="mt-5 grid gap-2">
              <button
                type="button"
                disabled={!file || phase === "working"}
                onClick={() => file && analyze(file, reference)}
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-white px-4 py-3 text-[13.5px] font-medium text-navy-950 transition-all hover:bg-navy-100 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {phase === "working" ? (
                  <>
                    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-navy-300 border-t-navy-950" />
                    Analyzing…
                  </>
                ) : (
                  <>
                    Run forensic analysis
                    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                      <path d="M3 8h10M9 4l4 4-4 4" />
                    </svg>
                  </>
                )}
              </button>
              {phase === "done" || phase === "error" ? (
                <button
                  type="button"
                  onClick={reset}
                  className="rounded-lg border border-navy-800 px-4 py-2.5 text-[12.5px] font-medium text-navy-200 transition-colors hover:border-navy-700 hover:text-white"
                >
                  New examination
                </button>
              ) : (
                <Link
                  href="/cases"
                  className="rounded-lg border border-navy-800 px-4 py-2.5 text-center text-[12.5px] font-medium text-navy-200 transition-colors hover:border-navy-700 hover:text-white"
                >
                  Case register
                </Link>
              )}
            </div>
          </div>
        </div>

        {phase === "error" && error ? (
          <div className="border-t border-hairline bg-[#fef4f3] px-5 py-3.5">
            <p className="flex items-start gap-2 text-[13px] text-[#a32117]">
              <svg viewBox="0 0 16 16" className="mt-0.5 h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.6">
                <circle cx="8" cy="8" r="6" />
                <path d="M8 5v4M8 11.2v.2" />
              </svg>
              {error}
            </p>
          </div>
        ) : null}
      </section>

      <div id="analysis-output">
        {report ? (
          <ReportDashboard report={report} assetUrl={assetUrl} />
        ) : phase === "working" ? (
          <div className="rounded-2xl border border-dashed border-navy-200 px-5 py-16 text-center">
            <p className="font-mono text-[11px] tracking-[0.16em] text-graphite-500 uppercase">
              {STAGES[stage]}…
            </p>
            <div className="mx-auto mt-5 h-1 w-56 overflow-hidden rounded-full bg-navy-100">
              <div
                className="h-full rounded-full bg-electric-600 transition-all duration-500"
                style={{ width: `${((stage + 1) / STAGES.length) * 100}%` }}
              />
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
