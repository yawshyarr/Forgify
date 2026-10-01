"use client";

import Link from "next/link";
import { useState } from "react";
import { Chip, Eyebrow, Reveal } from "@/components/ui/kit";

const FIELDS = [
  { name: "name", label: "Full name", placeholder: "Dr. A. Sharma", type: "text", required: true },
  { name: "email", label: "Institutional email", placeholder: "a.sharma@university.edu", type: "email", required: true },
  { name: "organisation", label: "Organisation / department", placeholder: "Dept. of Computer Engineering", type: "text", required: false },
];

export function FinalCta() {
  const [state, setState] = useState<"idle" | "sending" | "done" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [form, setForm] = useState<Record<string, string>>({ name: "", email: "", organisation: "", role: "Evaluator", message: "" });

  const update = (key: string, value: string) => setForm((prev) => ({ ...prev, [key]: value }));

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setState("sending");
    setError(null);
    try {
      const res = await fetch("/api/requests", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(form),
      });
      const json = (await res.json()) as { ok: boolean; error?: string };
      if (!res.ok || !json.ok) {
        setError(json.error ?? "Something went wrong.");
        setState("error");
        return;
      }
      setState("done");
    } catch {
      setError("Network error — please try again.");
      setState("error");
    }
  }

  return (
    <section id="access" className="bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <div className="overflow-hidden rounded-2xl border border-hairline bg-navy-950">
          <div className="grid gap-px bg-navy-900 lg:grid-cols-[1.05fr_0.95fr]">
            <div className="bg-navy-950 p-8 sm:p-10">
              <Eyebrow tone="#5c85ff">Get access</Eyebrow>
              <h2 className="mt-5 text-3xl leading-[1.1] font-semibold tracking-[-0.025em] text-white text-balance sm:text-[2.4rem]">
                Run your own exhibit through the eleven-layer engine.
              </h2>
              <p className="mt-5 max-w-lg text-[14.5px] leading-relaxed text-navy-300">
                The analysis workbench is live — upload a PDF or image and watch the full pipeline execute.
                Supervisors, evaluators and recruiters can request a walkthrough, the dataset documentation or the
                API contract using this form.
              </p>

              <div className="mt-8 grid gap-3 sm:grid-cols-2">
                {[
                  ["Open the workbench", "/analyze", "Upload, analyze, inspect every layer"],
                  ["Browse the case register", "/cases", "Every persisted examination with its report"],
                  ["Engine contract", "/api/layers", "Layers, weights and runtimes as JSON"],
                  ["How it works", "/#pipeline", "The eight-stage pipeline, end to end"],
                ].map(([label, href, sub]) => (
                  <Link
                    key={href}
                    href={href}
                    className="group rounded-xl border border-navy-800 bg-navy-900/40 p-4 transition-all duration-300 hover:border-electric-500 hover:bg-navy-900"
                  >
                    <p className="flex items-center gap-2 text-[13.5px] font-medium text-white">
                      {label}
                      <svg viewBox="0 0 16 16" className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" fill="none" stroke="#5c85ff" strokeWidth="1.7">
                        <path d="M3 8h10M9 4l4 4-4 4" />
                      </svg>
                    </p>
                    <p className="mt-1.5 text-[12px] leading-relaxed text-navy-300">{sub}</p>
                  </Link>
                ))}
              </div>

              <div className="mt-8 flex flex-wrap gap-2">
                <Chip tone="navy" className="border-navy-800 bg-navy-900 text-navy-200">
                  POST /api/analyze
                </Chip>
                <Chip tone="navy" className="border-navy-800 bg-navy-900 text-navy-200">
                  FastAPI/OpenCV bridge
                </Chip>
                <Chip tone="navy" className="border-navy-800 bg-navy-900 text-navy-200">
                  PostgreSQL case store
                </Chip>
              </div>
            </div>

            <div className="bg-white p-8 sm:p-10">
              {state === "done" ? (
                <div className="flex h-full flex-col items-start justify-center">
                  <span className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#f1faf6]">
                    <svg viewBox="0 0 20 20" className="h-5 w-5" fill="none" stroke="#0f6b4f" strokeWidth="1.8">
                      <path d="M4 10l4 4 8-9" />
                    </svg>
                  </span>
                  <h3 className="mt-5 text-[19px] font-semibold tracking-[-0.02em] text-navy-950">Request recorded</h3>
                  <p className="mt-3 max-w-sm text-[13.5px] leading-relaxed text-graphite-500">
                    Your details are stored in the case store and you will receive the walkthrough, dataset
                    documentation and evaluation report. In the meantime the workbench needs no approval —
                    go and analyze something.
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
                <form onSubmit={submit} className="grid gap-4">
                  <div>
                    <h3 className="text-[17px] font-semibold tracking-[-0.02em] text-navy-950">Request a walkthrough</h3>
                    <p className="mt-1.5 text-[12.5px] text-graphite-500">No account needed to analyze a document.</p>
                  </div>

                  {FIELDS.map((f) => (
                    <label key={f.name} className="grid gap-1.5">
                      <span className="font-mono text-[10px] tracking-[0.12em] text-graphite-500 uppercase">
                        {f.label}
                        {f.required ? <span className="text-[#b42318]"> *</span> : null}
                      </span>
                      <input
                        type={f.type}
                        required={f.required}
                        value={form[f.name] ?? ""}
                        placeholder={f.placeholder}
                        onChange={(e) => update(f.name, e.target.value)}
                        className="rounded-lg border border-hairline bg-white px-3.5 py-2.5 text-[13.5px] text-navy-950 outline-none transition-colors placeholder:text-navy-300 focus:border-electric-400"
                      />
                    </label>
                  ))}

                  <label className="grid gap-1.5">
                    <span className="font-mono text-[10px] tracking-[0.12em] text-graphite-500 uppercase">I am a…</span>
                    <select
                      value={form.role}
                      onChange={(e) => update("role", e.target.value)}
                      className="rounded-lg border border-hairline bg-white px-3.5 py-2.5 text-[13.5px] text-navy-950 outline-none focus:border-electric-400"
                    >
                      {["Evaluator", "Professor / supervisor", "Recruiter", "Forensics practitioner", "Student collaborator"].map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  </label>

                  <label className="grid gap-1.5">
                    <span className="font-mono text-[10px] tracking-[0.12em] text-graphite-500 uppercase">Anything specific?</span>
                    <textarea
                      rows={3}
                      value={form.message}
                      onChange={(e) => update("message", e.target.value)}
                      placeholder="Dataset documentation, model weights, viva demo…"
                      className="resize-none rounded-lg border border-hairline bg-white px-3.5 py-2.5 text-[13.5px] text-navy-950 outline-none transition-colors placeholder:text-navy-300 focus:border-electric-400"
                    />
                  </label>

                  {error ? <p className="rounded-lg bg-[#fef4f3] px-3 py-2 text-[12.5px] text-[#a32117]">{error}</p> : null}

                  <button
                    type="submit"
                    disabled={state === "sending"}
                    className="mt-1 inline-flex items-center justify-center gap-2 rounded-lg bg-navy-950 px-5 py-3 text-[13.5px] font-medium text-white transition-all hover:bg-navy-900 disabled:opacity-60"
                  >
                    {state === "sending" ? "Recording…" : "Request access"}
                    <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                      <path d="M3 8h10M9 4l4 4-4 4" />
                    </svg>
                  </button>
                  <p className="text-[11.5px] leading-relaxed text-graphite-500">
                    Only your name, email, organisation and role are stored, and solely to respond to this request.
                  </p>
                </form>
              )}
            </div>
          </div>
        </div>

        <Reveal delay={80}>
          <div className="mt-10 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-hairline bg-surface px-5 py-4">
            <p className="text-[13px] text-graphite-700">
              <span className="font-mono text-[10.5px] tracking-[0.12em] text-electric-600 uppercase">Viva-ready · </span>
              Every claim on this page maps to a module in the repository: detectors, fusion, API, persistence and UI.
            </p>
            <p className="font-mono text-[10.5px] tracking-[0.1em] text-graphite-500 uppercase">
              engine v2.4.0 · 11 layers · 8 stages
            </p>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
