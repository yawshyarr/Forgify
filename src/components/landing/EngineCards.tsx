"use client";

import { useMemo, useState } from "react";
import { Chip, Meter, Reveal, SectionHeading } from "@/components/ui/kit";
import { LAYERS } from "@/lib/forensics/registry";

const CATEGORY_TONE: Record<string, string> = {
  signal: "#1a3ff5",
  container: "#06b6d4",
  content: "#133a6f",
  manipulation: "#1630d8",
  intelligence: "#071122",
};

const SAMPLE_FINDINGS: Record<string, { code: string; title: string; severity: string; tone: string; metric: string; body: string }> = {
  pixel: {
    code: "PX-ELA",
    title: "Error-level residual diverges sharply in one region",
    severity: "Critical",
    tone: "#8f1d1d",
    metric: "ΔELA 11.4 dB",
    body: "Re-encoding at a +5 quantisation offset produced a localised residual hotspot against a uniform background — the region did not pass through the same compression generation as the surrounding pixels.",
  },
  compression: {
    code: "CP-GEN",
    title: "Evidence of more than one lossy generation",
    severity: "Medium",
    tone: "#b54708",
    metric: "2 grid phases",
    body: "Block-grid phase analysis shows sub-cell offset between two candidate 8×8 lattices with a second-order residual above the detection floor: the file was decoded and re-encoded after its original save.",
  },
  metadata: {
    code: "MD-TIME",
    title: "Timestamp paradox: modification predates creation",
    severity: "High",
    tone: "#b42318",
    metric: "−412 min",
    body: "The modification timestamp is earlier than the creation timestamp. Legal timestamps cannot be un-ordered unless a tool explicitly rewrote one of them — which is itself evidence of tampering.",
  },
  provenance: {
    code: "PR-MANIFEST",
    title: "No C2PA / JUMBF manifest present in the container",
    severity: "Medium",
    tone: "#b54708",
    metric: "no manifest",
    body: "Without an attested origin the exhibit cannot be positively attributed to a capture device or authoring tool, so every other layer must carry the identification burden.",
  },
  ocr: {
    code: "OCR-GLYPH",
    title: "Digit glyphs in the amount field do not match the document font model",
    severity: "High",
    tone: "#b42318",
    metric: "2.9× stroke variance",
    body: "Stroke-width variance inside the amount field is far above the page median and the digit set maps to a different font family: the numerals were substituted rather than typed in the authoring application.",
  },
  layout: {
    code: "LY-GRID",
    title: "3 elements sit off the reconstructed text grid",
    severity: "Medium",
    tone: "#b54708",
    metric: "+3.8% margin drift",
    body: "The dominant left margin governs most recovered elements, but inserted content breaks it — pasted objects rarely inherit the authoring application's snap grid.",
  },
  "copy-move": {
    code: "CM-CLONE",
    title: "Dense keypoint cluster shares one affine transform",
    severity: "Critical",
    tone: "#8f1d1d",
    metric: "184 RANSAC inliers",
    body: "Keypoint correspondences across two regions are explained by a single affine transform with low reprojection error — the geometric signature of content copied and pasted inside the same image.",
  },
  signature: {
    code: "SG-CRYPTO",
    title: "Digital signature does NOT cover the current revision",
    severity: "Critical",
    tone: "#8f1d1d",
    metric: "digest mismatch",
    body: "The stored PKCS#7 digest no longer matches a recomputation over the current byte range: bytes were added after signing. This is direct, cryptographic evidence of post-signature modification.",
  },
  "qr-barcode": {
    code: "QR-ECC",
    title: "Error-correction capacity consumed by overwriting",
    severity: "Medium",
    tone: "#b54708",
    metric: "22 modules recovered",
    body: "The symbol decodes but many modules required ECC recovery, clustered in a single quadrant. Uniform scan wear does not cluster; a patch placed over part of the code does.",
  },
  semantic: {
    code: "SE-ARITH",
    title: "Grand total does not equal the sum of line items",
    severity: "Critical",
    tone: "#8f1d1d",
    metric: "₹ 41,250.00 Δ",
    body: "Recomputing the recovered line items gives a different total to the printed grand total. The discrepancy is machine-checkable and survives re-encoding, printing and re-scanning.",
  },
  aigc: {
    code: "AI-SPEC",
    title: "Decoder spectral fingerprint present above detection floor",
    severity: "High",
    tone: "#b42318",
    metric: "6.8 dB grid peak",
    body: "The 2-D power spectrum contains periodic upsampler energy plus checkerboard artifacts in the top octave — the signature of a transposed-convolution decoder rather than an optical sensor.",
  },
};

export function EngineCards() {
  const [activeId, setActiveId] = useState<string>("pixel");
  const active = LAYERS.find((l) => l.id === activeId) ?? LAYERS[0];
  const sample = SAMPLE_FINDINGS[active.id];

  const bars = useMemo(() => {
    let seed = 0;
    for (const ch of active.id) seed = (seed * 31 + ch.charCodeAt(0)) % 9973;
    const out: number[] = [];
    for (let i = 0; i < 28; i++) {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      const base = 0.22 + ((seed >>> 8) % 100) / 100 * 0.7;
      const spike = active.id === "pixel" || active.id === "aigc" ? (i > 18 && i < 23 ? 0.95 : 0) : 0;
      out.push(Math.min(1, base * 0.55 + spike));
    }
    return out;
  }, [active.id]);

  return (
    <section id="engines" className="border-b border-hairline bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Interactive · forensic engines"
            title="Inspect each detector the way an examiner would"
            lead="Select a layer to see what it measures, which techniques it applies, how much weight it carries in the fusion and what one of its findings looks like in a real report."
          />
        </Reveal>

        <div className="mt-12 grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <Reveal>
            <div className="grid gap-1.5">
              {LAYERS.map((layer) => {
                const selected = layer.id === activeId;
                return (
                  <button
                    key={layer.id}
                    type="button"
                    onMouseEnter={() => setActiveId(layer.id)}
                    onClick={() => setActiveId(layer.id)}
                    className={`group flex items-center gap-3 rounded-lg border px-3.5 py-2.5 text-left transition-all duration-200 ${
                      selected ? "border-navy-200 bg-navy-50 shadow-[var(--shadow-card)]" : "border-hairline bg-white hover:border-navy-200"
                    }`}
                  >
                    <span
                      className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md font-mono text-[9.5px] font-semibold text-white transition-transform duration-200 group-hover:scale-105"
                      style={{ background: layer.accent }}
                    >
                      {layer.glyph}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className={`block truncate text-[13.5px] font-medium ${selected ? "text-navy-950" : "text-graphite-700"}`}>
                        {layer.name}
                      </span>
                      <span className="mt-0.5 block truncate font-mono text-[10px] tracking-[0.06em] text-graphite-500 uppercase">
                        {layer.tagline}
                      </span>
                    </span>
                    <span className="w-16 shrink-0">
                      <Meter value={layer.weight / 0.17} color={selected ? layer.accent : "#c8d6ea"} height={4} animate={false} />
                    </span>
                    <span className="tabular w-8 shrink-0 text-right font-mono text-[10px] text-graphite-500">
                      {layer.weight.toFixed(2)}
                    </span>
                  </button>
                );
              })}
            </div>
          </Reveal>

          <Reveal delay={90}>
            <div className="flex h-full flex-col overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-5 py-4">
                <div className="flex items-center gap-3">
                  <span className="flex h-9 w-9 items-center justify-center rounded-lg font-mono text-[10.5px] font-semibold text-white" style={{ background: active.accent }}>
                    {active.glyph}
                  </span>
                  <div>
                    <h3 className="text-[15.5px] font-semibold tracking-[-0.015em] text-navy-950">{active.name}</h3>
                    <p className="font-mono text-[10px] tracking-[0.1em] text-graphite-500 uppercase">{active.tagline}</p>
                  </div>
                </div>
                <Chip tone="outline">{CATEGORY_TONE[active.category] ? active.category : "layer"} layer</Chip>
              </div>

              <div className="border-b border-hairline bg-surface px-5 py-5">
                <div className="flex items-end gap-[3px]" style={{ height: 84 }}>
                  {bars.map((b, i) => (
                    <span
                      key={i}
                      className="flex-1 rounded-t-[2px] transition-all duration-500"
                      style={{
                        height: `${b * 100}%`,
                        background: b > 0.8 ? "#b42318" : active.accent,
                        opacity: b > 0.8 ? 1 : 0.72,
                      }}
                    />
                  ))}
                </div>
                <div className="mt-3 flex items-center justify-between font-mono text-[9.5px] tracking-[0.1em] text-graphite-500 uppercase">
                  <span>{active.techniques[0]} · response histogram</span>
                  <span className="text-[#b42318]">threshold breach</span>
                </div>
              </div>

              <div className="flex-1 px-5 py-5">
                <p className="text-[13.5px] leading-relaxed text-graphite-500">{active.description}</p>
                <div className="mt-4 flex flex-wrap gap-1.5">
                  {active.techniques.map((t) => (
                    <span key={t} className="rounded-md border border-hairline px-2 py-1 font-mono text-[9.5px] text-navy-700">
                      {t}
                    </span>
                  ))}
                </div>

                {sample ? (
                  <div className="mt-5 rounded-xl border p-4" style={{ borderColor: `${sample.tone}33`, background: `${sample.tone}08` }}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded px-1.5 py-0.5 font-mono text-[9.5px] tracking-[0.1em] uppercase" style={{ background: `${sample.tone}14`, color: sample.tone }}>
                        {sample.severity}
                      </span>
                      <span className="font-mono text-[10px] tracking-[0.1em] text-graphite-500 uppercase">{sample.code}</span>
                      <span className="tabular ml-auto font-mono text-[11px]" style={{ color: sample.tone }}>
                        {sample.metric}
                      </span>
                    </div>
                    <p className="mt-2.5 text-[13.5px] leading-snug font-semibold text-navy-950">{sample.title}</p>
                    <p className="mt-1.5 text-[12.5px] leading-relaxed text-graphite-500">{sample.body}</p>
                  </div>
                ) : null}
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-hairline bg-navy-50/50 px-5 py-3.5">
                <p className="font-mono text-[10px] tracking-[0.08em] text-graphite-500">{`runtime · ${active.id}.detector`}</p>
                <p className="font-mono text-[10px] tracking-[0.08em] text-graphite-500 uppercase">
                  fusion weight {active.weight.toFixed(2)}
                </p>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
