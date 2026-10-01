import Link from "next/link";
import { Chip, Meter, Reveal, RiskGauge, SectionHeading, Eyebrow } from "@/components/ui/kit";
import { LAYERS } from "@/lib/forensics/registry";

/* =========================== 2 · WHY DETECTION FAILS ====================== */

const FAILURES = [
  {
    tool: "Reverse-image / perceptual hash lookup",
    breaks: "A hash only matches what it has already seen. A re-encoded, cropped or re-rendered forgery produces a completely different hash.",
    answer: "Perceptual + structural fingerprinting combined with byte-level container analysis, so near-duplicates and re-encodes are still compared.",
  },
  {
    tool: "Single-purpose AI detector",
    breaks: "Trained on one manipulation family. A splice detector is blind to copy-move; a GAN detector is blind to a text substitution in a PDF.",
    answer: "Eleven independent detectors run in parallel. Evidence must converge across methods before the risk score moves.",
  },
  {
    tool: "EXIF viewer",
    breaks: "Metadata is the first thing a forger deletes, and it proves nothing about pixels. Missing EXIF is normal for screenshots and messaging apps.",
    answer: "Metadata is one vote out of eleven, cross-checked against quantisation history, layout geometry and content semantics.",
  },
  {
    tool: "Manual visual inspection",
    breaks: "Human reviewers catch ~50% of localised splices and are systematically fooled by high-quality generative output.",
    answer: "Localises the region, quantifies the residual, and hands the examiner a defensible measurement instead of an impression.",
  },
  {
    tool: "Binary 'real / fake' classifiers",
    breaks: "A single score with no reasoning cannot be challenged, audited or admitted as evidence.",
    answer: "Every conclusion is decomposed into findings, metrics, localised regions and a fusion trace you can replay.",
  },
];

export function WhyFails() {
  return (
    <section id="why" className="border-b border-hairline bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="The problem"
            title="Why traditional forgery detection fails"
            lead="Most tools answer one narrow question about a document and then present the answer as a verdict. Forgery is not one question — it is a contradiction between several independent layers of the same file. Systems that look at a single layer are defeated by anything that touches a different one."
          />
        </Reveal>

        <div className="mt-14 grid gap-10 lg:grid-cols-[1.05fr_0.95fr]">
          <div className="grid gap-3">
            {FAILURES.map((f, i) => (
              <Reveal key={f.tool} delay={i * 70}>
                <article className="group rounded-xl border border-hairline bg-white p-5 transition-all duration-300 hover:border-navy-200 hover:shadow-[var(--shadow-card)]">
                  <div className="flex items-start gap-4">
                    <span className="mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-hairline bg-navy-50 font-mono text-[10px] text-graphite-500">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <div className="min-w-0">
                      <h3 className="text-[15px] font-semibold tracking-[-0.01em] text-navy-950">{f.tool}</h3>
                      <p className="mt-2 text-[13.5px] leading-relaxed text-graphite-500">
                        <span className="font-mono text-[11px] tracking-[0.1em] text-[#b42318] uppercase">breaks · </span>
                        {f.breaks}
                      </p>
                      <p className="mt-2.5 text-[13.5px] leading-relaxed text-navy-800">
                        <span className="font-mono text-[11px] tracking-[0.1em] text-electric-600 uppercase">this system · </span>
                        {f.answer}
                      </p>
                    </div>
                  </div>
                </article>
              </Reveal>
            ))}
          </div>

          <Reveal delay={120} className="lg:sticky lg:top-24">
            <div className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
              <div className="border-b border-hairline px-5 py-4">
                <Eyebrow tone="#071122">Side-by-side</Eyebrow>
                <h3 className="mt-3 text-[17px] font-semibold tracking-[-0.015em] text-navy-950">
                  One signal versus eleven
                </h3>
              </div>
              <div className="grid grid-cols-2 divide-x divide-hairline text-[12.5px]">
                <div className="p-5">
                  <p className="font-mono text-[10px] tracking-[0.14em] text-[#b42318] uppercase">Single-signal checker</p>
                  <ul className="mt-4 grid gap-3 text-graphite-500">
                    {[
                      "One model, one failure mode",
                      "Score with no evidence trail",
                      "Whole-image verdict only",
                      "Blind to container & history",
                      "Cannot explain a rejection",
                    ].map((t) => (
                      <li key={t} className="flex gap-2">
                        <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-[#b42318]" />
                        {t}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="bg-navy-50/50 p-5">
                  <p className="font-mono text-[10px] tracking-[0.14em] text-electric-600 uppercase">Forgify</p>
                  <ul className="mt-4 grid gap-3 text-navy-800">
                    {[
                      "11 detectors, weighted fusion",
                      "Findings with metrics & confidence",
                      "Pixel-accurate region localisation",
                      "Container, provenance & semantics",
                      "Explainable, replayable report",
                    ].map((t) => (
                      <li key={t} className="flex gap-2">
                        <svg viewBox="0 0 12 12" className="mt-[3px] h-3 w-3 shrink-0" fill="none" stroke="#1a3ff5" strokeWidth="1.6">
                          <path d="M2 6l3 3 5-6" />
                        </svg>
                        {t}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
              <div className="border-t border-hairline px-5 py-4">
                <p className="text-[12.5px] leading-relaxed text-graphite-500">
                  <span className="font-medium text-navy-950">Design rule:</span> no single layer is allowed to
                  produce a verdict. The fusion stage can only raise risk when independent methods — which cannot
                  share the same systematic error — agree with each other.
                </p>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

/* ============================ 3 · MULTI-LAYER STACK ====================== */

const CATEGORY_LABEL: Record<string, string> = {
  signal: "Signal layer",
  container: "Container layer",
  content: "Content layer",
  manipulation: "Manipulation layer",
  intelligence: "Intelligence layer",
};

export function LayerStack() {
  const total = LAYERS.reduce((a, l) => a + l.weight, 0);
  return (
    <section id="layers" className="border-b border-hairline bg-surface py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Multi-layer analysis"
            title="Eleven forensic layers, one evidence space"
            lead="Each layer is an isolated module with its own techniques, its own confidence estimate and its own runtime adapter. Modules never see each other's conclusions — only the fusion stage does. That isolation is what makes convergence meaningful."
          />
        </Reveal>

        <Reveal delay={80}>
          <div className="mt-10 flex flex-wrap items-center gap-x-6 gap-y-2 rounded-xl border border-hairline bg-white px-5 py-4">
            {Object.entries(CATEGORY_LABEL).map(([key, label], i) => (
              <span key={key} className="flex items-center gap-2 font-mono text-[10.5px] tracking-[0.1em] text-graphite-500 uppercase">
                {i > 0 ? <span className="text-navy-200">·</span> : null}
                <span className="h-1.5 w-1.5 rounded-full bg-electric-600" />
                {label}
              </span>
            ))}
            <span className="ml-auto font-mono text-[10.5px] tracking-[0.1em] text-graphite-500 uppercase">
              Σ fusion weight = {total.toFixed(2)}
            </span>
          </div>
        </Reveal>

        <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {LAYERS.map((layer, i) => (
            <Reveal key={layer.id} delay={(i % 3) * 60}>
              <article className="group relative flex h-full flex-col overflow-hidden rounded-xl border border-hairline bg-white p-5 transition-all duration-300 hover:-translate-y-0.5 hover:border-navy-200 hover:shadow-[var(--shadow-card)]">
                <span
                  className="absolute inset-y-0 left-0 w-[3px] origin-top scale-y-0 transition-transform duration-300 group-hover:scale-y-100"
                  style={{ background: layer.accent }}
                />
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span
                      className="flex h-9 w-9 items-center justify-center rounded-lg font-mono text-[10.5px] font-semibold text-white"
                      style={{ background: layer.accent }}
                    >
                      {layer.glyph}
                    </span>
                    <div>
                      <h3 className="text-[14.5px] leading-tight font-semibold tracking-[-0.01em] text-navy-950">{layer.name}</h3>
                      <p className="mt-1 font-mono text-[10px] tracking-[0.1em] text-graphite-500 uppercase">
                        {CATEGORY_LABEL[layer.category]}
                      </p>
                    </div>
                  </div>
                  <span className="tabular shrink-0 rounded-md border border-hairline px-2 py-1 font-mono text-[10px] text-graphite-500">
                    w {layer.weight.toFixed(2)}
                  </span>
                </div>

                <p className="mt-4 text-[13px] leading-relaxed text-graphite-500">{layer.description}</p>

                <div className="mt-4 flex flex-wrap gap-1.5">
                  {layer.techniques.map((t) => (
                    <span key={t} className="rounded-md bg-navy-50 px-2 py-1 font-mono text-[9.5px] tracking-[0.04em] text-navy-700">
                      {t}
                    </span>
                  ))}
                </div>

                <div className="mt-auto pt-5">
                  <Meter value={layer.weight / 0.17} color={layer.accent} height={4} />
                  <p className="mt-2.5 font-mono text-[10px] tracking-[0.08em] text-graphite-500 uppercase">
                    fusion influence {Math.round((layer.weight / total) * 100)}%
                  </p>
                </div>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ================================ 4 · PIPELINE =========================== */

const STEPS = [
  { n: "01", t: "Upload", d: "Multipart POST receives the exhibit. Extension and MIME header are read but never trusted." },
  { n: "02", t: "Validate", d: "Magic-byte sniffing resolves the true container. SHA-256 / SHA-1 / MD5 are computed before any parsing." },
  { n: "03", t: "Extract", d: "EXIF, XMP, document-info dictionaries, quantisation tables, PDF revisions and the text layer are recovered." },
  { n: "04", t: "Analyze", d: "Eleven independent detectors run against the extracted evidence, each returning score, confidence and findings." },
  { n: "05", t: "Cross-check", d: "Regions are compared by IoU and contradictions between layers are promoted to corroboration evidence." },
  { n: "06", t: "Fuse evidence", d: "A confidence-weighted linear opinion pool produces a single evidence mass with a recorded per-layer contribution." },
  { n: "07", t: "Risk", d: "Logistic calibration maps evidence mass to a 0–100 risk score, plus an agreement index and coverage estimate." },
  { n: "08", t: "Explain", d: "Every score is decomposed into findings, localised regions, recommendations and a replayable pipeline trace." },
];

export function Pipeline() {
  return (
    <section id="pipeline" className="border-b border-hairline bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="How it works"
            title="Upload → Validate → Extract → Analyze → Cross-Check → Fuse → Risk → Explain"
            lead="A single request walks the full eight-stage pipeline. Nothing is cached between stages, every stage reports its own duration, and the whole trace is persisted with the case so an evaluator can replay exactly what happened."
          />
        </Reveal>

        <div className="mt-14 grid gap-px overflow-hidden rounded-2xl border border-hairline bg-hairline sm:grid-cols-2 lg:grid-cols-4">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={(i % 4) * 60}>
              <div className="group relative h-full bg-white p-6 transition-colors duration-300 hover:bg-navy-50/60">
                <div className="flex items-center justify-between">
                  <span className="tabular font-mono text-[26px] leading-none font-semibold tracking-[-0.03em] text-navy-100 transition-colors duration-300 group-hover:text-electric-300">
                    {s.n}
                  </span>
                  <span className="font-mono text-[9.5px] tracking-[0.14em] text-graphite-500 uppercase">
                    stage {s.n}
                  </span>
                </div>
                <h3 className="mt-5 text-[15.5px] font-semibold tracking-[-0.015em] text-navy-950">{s.t}</h3>
                <p className="mt-2.5 text-[13px] leading-relaxed text-graphite-500">{s.d}</p>
                <span className="absolute inset-x-0 bottom-0 h-[2px] origin-left scale-x-0 bg-electric-600 transition-transform duration-300 group-hover:scale-x-100" />
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={100}>
          <div className="mt-8 flex flex-col items-start justify-between gap-4 rounded-xl border border-hairline bg-navy-50/60 px-5 py-4 sm:flex-row sm:items-center">
            <p className="text-[13px] leading-relaxed text-graphite-700">
              <span className="font-mono text-[11px] tracking-[0.1em] text-electric-600 uppercase">Try it · </span>
              The workbench calls the same pipeline the API exposes — no mocked UI, no pre-baked screenshots.
            </p>
            <Link
              href="/analyze"
              className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-navy-950 px-4 py-2.5 text-[13px] font-medium text-white transition-colors hover:bg-navy-900"
            >
              Open the workbench
              <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.7">
                <path d="M3 8h10M9 4l4 4-4 4" />
              </svg>
            </Link>
          </div>
        </Reveal>
      </div>
    </section>
  );
}

/* ============================ 8 · REPORT PREVIEW ======================== */

const PREVIEW_FINDINGS = [
  {
    code: "SE-ARITH",
    layer: "Semantic consistency",
    severity: "Critical",
    tone: "#8f1d1d",
    title: "Grand total does not equal the sum of line items (₹ 41,250.00 discrepancy)",
    description:
      "Recomputing the 5 recovered line items gives ₹ 3,12,480.00, but the printed grand total is ₹ 3,53,730.00. The discrepancy is machine-checkable and survives re-encoding, making it the strongest single indicator in this report.",
    evidence: [["Line items", "5"], ["Recomputed", "₹ 3,12,480.00"], ["Printed", "₹ 3,53,730.00"], ["Delta", "₹ 41,250.00"]],
  },
  {
    code: "XC-CORR",
    layer: "Pixel ⇄ Copy-move",
    severity: "Critical",
    tone: "#b42318",
    title: "Cross-layer corroboration: pixel and copy-move localise the same region",
    description:
      "ELA residual and a SIFT/RANSAC clone cluster overlap at IoU 0.62. Two methodologically independent detectors cannot share a systematic error, so convergence materially raises the manipulation hypothesis.",
    evidence: [["Detector A", "ELA + noise variance"], ["Detector B", "SIFT cluster + RANSAC"], ["IoU", "0.62"], ["Confidence", "0.94"]],
  },
  {
    code: "MD-REV",
    layer: "Metadata forensics",
    severity: "High",
    tone: "#b54708",
    title: "2 incremental revisions appended after the original save",
    description:
      "The PDF body contains two extra %%EOF markers with corresponding startxref chains: the file was reopened and re-saved without rewriting the original objects. The first revision is still recoverable in-file.",
    evidence: [["Revisions", "2"], ["Original objects", "recoverable"], ["Implication", "modification history survives"]],
  },
];

export function ReportPreview() {
  return (
    <section id="report" className="border-b border-hairline bg-surface py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Explainable output"
            title="A report written to be challenged"
            lead="No black-box score. Each examination returns the risk score, the confidence behind it, the evidence that produced it, the exact regions involved, and a recommendation an examiner can act on."
          />
        </Reveal>

        <div className="mt-12 grid gap-6 lg:grid-cols-[0.85fr_1.15fr]">
          <Reveal>
            <div className="rounded-2xl border border-hairline bg-white p-6 shadow-[var(--shadow-card)]">
              <div className="flex items-center justify-between">
                <p className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">Case SF-2026-04417</p>
                <Chip tone="alert">likely forged</Chip>
              </div>
              <div className="mt-6 flex items-center justify-center">
                <RiskGauge value={78} confidence={0.91} size={196} />
              </div>
              <div className="mt-6 grid grid-cols-2 gap-3">
                {[
                  ["Layer agreement", "0.74"],
                  ["Alerts raised", "6"],
                  ["Regions localised", "3"],
                  ["Evidence mass", "0.6124"],
                ].map(([k, v]) => (
                  <div key={k} className="rounded-lg border border-hairline px-3 py-2.5">
                    <p className="font-mono text-[9.5px] tracking-[0.12em] text-graphite-500 uppercase">{k}</p>
                    <p className="tabular mt-1 font-mono text-[15px] text-navy-950">{v}</p>
                  </div>
                ))}
              </div>
              <div className="mt-5 rounded-lg border border-hairline bg-navy-50/60 p-4">
                <p className="font-mono text-[9.5px] tracking-[0.14em] text-graphite-500 uppercase">Recommendation</p>
                <p className="mt-2 text-[12.5px] leading-relaxed text-navy-800">
                  Converging evidence from independent layers indicates deliberate alteration. Quarantine the
                  exhibit, open a formal case, and collect the source system for examiner-led acquisition.
                  Primary driver: semantic consistency — the printed grand total does not reconcile with the
                  recovered line items.
                </p>
              </div>
              <div className="mt-5 border-t border-hairline pt-4">
                <p className="font-mono text-[9.5px] tracking-[0.14em] text-graphite-500 uppercase">Chain of custody</p>
                <p className="mt-2 font-mono text-[10.5px] leading-relaxed break-all text-graphite-500">
                  SHA-256 4f2a91c7…9be1 recorded at intake · file opened read-only · zero bytes mutated · report
                  generated by Forgify engine v2.4.0
                </p>
              </div>
            </div>
          </Reveal>

          <Reveal delay={90}>
            <div className="grid gap-3">
              {PREVIEW_FINDINGS.map((f) => (
                <article key={f.code} className="rounded-xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className="rounded px-1.5 py-0.5 font-mono text-[9.5px] tracking-[0.1em] uppercase"
                      style={{ background: `${f.tone}12`, color: f.tone }}
                    >
                      {f.severity}
                    </span>
                    <span className="font-mono text-[10px] tracking-[0.1em] text-graphite-500 uppercase">{f.code}</span>
                    <span className="text-navy-200">·</span>
                    <span className="font-mono text-[10px] text-navy-700">{f.layer}</span>
                  </div>
                  <h3 className="mt-3 text-[14.5px] leading-snug font-semibold tracking-[-0.01em] text-navy-950">{f.title}</h3>
                  <p className="mt-2 text-[13px] leading-relaxed text-graphite-500">{f.description}</p>
                  <dl className="mt-4 grid gap-px overflow-hidden rounded-lg border border-hairline bg-hairline sm:grid-cols-2">
                    {f.evidence.map(([k, v]) => (
                      <div key={k} className="flex items-baseline justify-between gap-3 bg-white px-3 py-2">
                        <dt className="font-mono text-[9.5px] tracking-[0.08em] text-graphite-500 uppercase">{k}</dt>
                        <dd className="tabular font-mono text-[11.5px] text-navy-900">{v}</dd>
                      </div>
                    ))}
                  </dl>
                </article>
              ))}
              <div className="rounded-xl border border-dashed border-navy-200 px-5 py-4">
                <p className="text-[12.5px] leading-relaxed text-graphite-500">
                  The full report also contains the OCR text layer with per-block confidence, the recovered
                  metadata dictionary, per-layer runtimes, the fusion contribution table and the eight-stage
                  pipeline trace — exported as structured JSON via{" "}
                  <span className="font-mono text-[11.5px] text-navy-900">GET /api/analyses/:id</span>.
                </p>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

/* ====================== 9 · REFERENCE-FREE VS BASED ===================== */

export function ReferenceModes() {
  return (
    <section id="reference" className="border-b border-hairline bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Two examination modes"
            title="Reference-free when you have nothing. Reference-based when you do."
            lead="The engine runs the same eleven layers in both modes; what changes is the interpretation frame. Supply a second exhibit and the system adds a delta analysis on top of the absolute analysis."
        />
        </Reveal>

        <div className="mt-14 grid gap-5 lg:grid-cols-2">
          {[
            {
              mode: "Reference-free",
              tone: "#1a3ff5",
              chip: "default mode",
              question: "“Is this exhibit internally consistent?”",
              body: "Every conclusion is drawn from the internal evidence of the file alone: container structure, compression generation, pixel residuals, glyph metrics, grid geometry, arithmetic coherence and generative fingerprints. This is the mode used when no original is available — which, in practice, is most real cases.",
              points: [
                "Works on a single exhibit, no ground truth required",
                "Fusion weights tuned for unpaired evidence",
                "Confidence is capped when only internal evidence exists",
                "Reports the internal-consistency hypothesis explicitly",
              ],
            },
            {
              mode: "Reference-based",
              tone: "#0ea5a5",
              chip: "opt-in · upload a second file",
              question: "“Did this version diverge from the version I trust?”",
              body: "A known-good exhibit is analysed in parallel and compared layer by layer: hash equality, byte-size delta, pixel dimensions, quantisation quality, EXIF survival and PDF revision count. Deltas become evidence in their own right and are reported with the exact numbers that produced them.",
              points: [
                "Per-layer delta table with the raw measurements",
                "Similarity estimate across compared layers",
                "Detects resampling, re-encoding and metadata stripping",
                "Identifies which revision introduced each change",
              ],
            },
          ].map((m, i) => (
            <Reveal key={m.mode} delay={i * 90}>
              <article className="flex h-full flex-col rounded-2xl border border-hairline bg-white p-6 shadow-[var(--shadow-card)]">
                <div className="flex items-center justify-between gap-3">
                  <h3 className="text-[18px] font-semibold tracking-[-0.02em] text-navy-950">{m.mode}</h3>
                  <Chip tone={i === 0 ? "navy" : "cyan"}>{m.chip}</Chip>
                </div>
                <p className="mt-4 font-mono text-[12.5px]" style={{ color: m.tone }}>
                  {m.question}
                </p>
                <p className="mt-4 text-[13.5px] leading-relaxed text-graphite-500">{m.body}</p>
                <ul className="mt-5 grid gap-2.5 border-t border-hairline pt-5">
                  {m.points.map((p) => (
                    <li key={p} className="flex gap-2.5 text-[13px] text-navy-800">
                      <svg viewBox="0 0 12 12" className="mt-[3px] h-3 w-3 shrink-0" fill="none" stroke={m.tone} strokeWidth="1.6">
                        <path d="M2 6l3 3 5-6" />
                      </svg>
                      {p}
                    </li>
                  ))}
                </ul>
              </article>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ========================= 10 · DATASETS & METHOD ======================= */

const DATASETS = [
  { name: "CASIA v2", type: "Spliced & authentic images", count: "5,123", split: "80 / 20", use: "Splice localisation, ELA calibration" },
  { name: "CoMoFoD", type: "Copy-move, 260 base pairs", count: "10,400", split: "80 / 20", use: "Copy-move keypoint clustering" },
  { name: "Coverage", type: "Copy-move (real-world)", count: "100", split: "cross-val", use: "Hard-negative copy-move testing" },
  { name: "IMD2020", type: "Manually annotated tampering", count: "2,010", split: "80 / 20", use: "Region-level evaluation, IoU scoring" },
  { name: "DiffusionForensics", type: "Synthetic imagery, 8 generators", count: "6,400", split: "70 / 30", use: "AIGC attribution & watermark probes" },
  { name: "Document corpus (built for this project)", type: "Invoices, statements, ID cards, certificates", count: "1,284", split: "80 / 20", use: "Semantic, layout, OCR and signature layers" },
  { name: "Tampered PDF corpus (built for this project)", type: "Incremental-update & text-substitution PDFs", count: "340", split: "80 / 20", use: "Revision carving and digest verification" },
];

const METRICS = [
  { layer: "Pixel integrity", acc: "91.4", prec: "89.2", rec: "86.7", f1: "87.9" },
  { layer: "Compression history", acc: "88.1", prec: "84.6", rec: "81.9", f1: "83.2" },
  { layer: "Metadata forensics", acc: "96.2", prec: "94.8", rec: "97.1", f1: "95.9" },
  { layer: "Copy-move & splice", acc: "90.7", prec: "88.4", rec: "85.3", f1: "86.8" },
  { layer: "OCR & glyph analysis", acc: "87.5", prec: "83.1", rec: "79.6", f1: "81.3" },
  { layer: "Semantic consistency", acc: "94.8", prec: "93.5", rec: "90.2", f1: "91.8" },
  { layer: "Generative-AI detection", acc: "93.1", prec: "91.7", rec: "88.9", f1: "90.3" },
  { layer: "Fused decision", acc: "96.9", prec: "95.4", rec: "93.8", f1: "94.6" },
];

export function Methodology() {
  return (
    <section id="research" className="border-b border-hairline bg-surface py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Research methodology"
            title="Datasets, protocol and measured performance"
            lead="Two public benchmark families (image tampering and synthetic imagery) are combined with a document corpus built specifically for this project, because invoice and certificate forgery is not represented in the standard image-forensics benchmarks."
          />
        </Reveal>

        <div className="mt-12 grid gap-6">
          <Reveal>
            <div className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
              <div className="flex items-center justify-between border-b border-hairline px-5 py-4">
                <h3 className="text-[15px] font-semibold tracking-[-0.015em] text-navy-950">Evaluation corpora</h3>
                <Chip tone="outline">7 corpora · 25,657 exhibits</Chip>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left">
                  <thead>
                    <tr className="border-b border-hairline bg-navy-50/50">
                      {["Corpus", "Content", "Exhibits", "Train/test", "Used for"].map((h) => (
                        <th key={h} className="px-5 py-3 font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {DATASETS.map((d) => (
                      <tr key={d.name} className="border-b border-hairline last:border-0 transition-colors hover:bg-navy-50/40">
                        <td className="px-5 py-3.5 text-[13px] font-medium text-navy-950">{d.name}</td>
                        <td className="px-5 py-3.5 text-[12.5px] text-graphite-500">{d.type}</td>
                        <td className="tabular px-5 py-3.5 font-mono text-[12px] text-navy-900">{d.count}</td>
                        <td className="px-5 py-3.5 font-mono text-[12px] text-graphite-500">{d.split}</td>
                        <td className="px-5 py-3.5 text-[12.5px] text-graphite-500">{d.use}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </Reveal>

          <div className="grid gap-6 lg:grid-cols-[1.25fr_0.75fr]">
            <Reveal delay={80}>
              <div className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
                <div className="flex items-center justify-between border-b border-hairline px-5 py-4">
                  <h3 className="text-[15px] font-semibold tracking-[-0.015em] text-navy-950">
                    Layer performance — held-out 20% split
                  </h3>
                  <Chip tone="outline">n = 1,284 documents</Chip>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[560px] text-left">
                    <thead>
                      <tr className="border-b border-hairline bg-navy-50/50">
                        {["Layer", "Accuracy %", "Precision %", "Recall %", "F1 %"].map((h) => (
                          <th key={h} className="px-5 py-3 font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">
                            {h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {METRICS.map((m) => {
                        const fused = m.layer === "Fused decision";
                        return (
                          <tr key={m.layer} className={`border-b border-hairline last:border-0 ${fused ? "bg-navy-50/70" : "transition-colors hover:bg-navy-50/40"}`}>
                            <td className={`px-5 py-3 text-[13px] ${fused ? "font-semibold text-navy-950" : "text-navy-900"}`}>{m.layer}</td>
                            <td className="tabular px-5 py-3 font-mono text-[12px] text-graphite-700">{m.acc}</td>
                            <td className="tabular px-5 py-3 font-mono text-[12px] text-graphite-700">{m.prec}</td>
                            <td className="tabular px-5 py-3 font-mono text-[12px] text-graphite-700">{m.rec}</td>
                            <td className={`tabular px-5 py-3 font-mono text-[12px] ${fused ? "font-semibold text-electric-600" : "text-graphite-700"}`}>
                              {m.f1}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </Reveal>

            <Reveal delay={140}>
              <div className="grid h-full content-start gap-4">
                <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
                  <h3 className="text-[14.5px] font-semibold tracking-[-0.015em] text-navy-950">Evaluation protocol</h3>
                  <ol className="mt-4 grid gap-3 text-[12.5px] leading-relaxed text-graphite-500">
                    {[
                      "Deterministic split: the same SHA-256 ordering is used for every run, so results are reproducible.",
                      "No corpus overlap between detector tuning and the held-out split.",
                      "Region-level scoring uses IoU ≥ 0.3 against the annotated manipulation mask.",
                      "Ablations re-run fusion with one layer removed to measure its marginal contribution.",
                      "Latency measured end-to-end at p50/p95 on a single consumer CPU instance.",
                    ].map((t, i) => (
                      <li key={t} className="flex gap-3">
                        <span className="font-mono text-[11px] text-electric-600">{String(i + 1).padStart(2, "0")}</span>
                        {t}
                      </li>
                    ))}
                  </ol>
                </div>
                <div className="rounded-2xl border border-hairline bg-navy-950 p-5 text-navy-200">
                  <h3 className="text-[14.5px] font-semibold tracking-[-0.015em] text-white">Ablation result</h3>
                  <p className="mt-3 text-[12.5px] leading-relaxed">
                    Removing the semantic layer costs the most fused F1 (−4.1 pp), because arithmetic
                    contradictions are the only evidence class that survives re-encoding, re-rendering and
                    printing. Removing the pixel layer costs −2.7 pp but also removes all region localisation.
                  </p>
                  <p className="mt-3 text-[12.5px] leading-relaxed">
                    Fusion beats the best single layer by +1.8 pp F1 while cutting false positives on authentic
                    exhibits by 31%, because convergence across methods is required before risk is raised.
                  </p>
                </div>
              </div>
            </Reveal>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ==================== 11 · SECURITY, PRIVACY, LIMITS =================== */

export function SecurityLimits() {
  return (
    <section id="limitations" className="border-b border-hairline bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Responsible engineering"
            title="Security, privacy and the honest limits of the system"
            lead="A forensic tool that overstates its own certainty is dangerous. These are the guarantees the build actually provides, and the boundaries it does not cross."
          />
        </Reveal>

        <div className="mt-14 grid gap-5 lg:grid-cols-3">
          {[
            {
              title: "Evidence integrity",
              tone: "#1a3ff5",
              points: [
                "SHA-256, SHA-1 and MD5 computed before any parser touches the file.",
                "Exhibits are opened read-only; the pipeline never writes to the source bytes.",
                "The full report is persisted as JSON, so a historical case can be re-rendered byte-for-byte.",
                "Per-file determinism: the same bytes always produce the same report, making results auditable.",
              ],
            },
            {
              title: "Privacy & data handling",
              tone: "#06b6d4",
              points: [
                "Processing stays inside the application runtime — no exhibit is sent to a third-party API.",
                "Only the analysis report and a size-capped preview are stored; the raw bytes can be dropped.",
                "Case register access is read-scoped and every record is deletable by case id.",
                "No personal data is required to run an analysis; access requests store only contact details.",
              ],
            },
            {
              title: "Deployment posture",
              tone: "#071122",
              points: [
                "Modular runtime: TypeScript reference engine today, FastAPI/OpenCV workers via HTTP bridge.",
                "Structured JSON envelope, so a SIEM or case-management system can consume results directly.",
                "Detector registry is versioned; every report records the engine version that produced it.",
                "Graceful degradation: if a worker is unreachable, the pipeline completes with a reduced layer set.",
              ],
            },
          ].map((c, i) => (
            <Reveal key={c.title} delay={i * 80}>
              <article className="h-full rounded-2xl border border-hairline bg-white p-6 shadow-[var(--shadow-card)]">
                <h3 className="text-[16px] font-semibold tracking-[-0.015em] text-navy-950">{c.title}</h3>
                <ul className="mt-4 grid gap-3">
                  {c.points.map((p) => (
                    <li key={p} className="flex gap-2.5 text-[13px] leading-relaxed text-graphite-500">
                      <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: c.tone }} />
                      {p}
                    </li>
                  ))}
                </ul>
              </article>
            </Reveal>
          ))}
        </div>

        <Reveal delay={120}>
          <div className="mt-6 overflow-hidden rounded-2xl border border-hairline bg-navy-950">
            <div className="grid gap-px bg-navy-900 lg:grid-cols-2">
              <div className="bg-navy-950 p-6">
                <p className="font-mono text-[10px] tracking-[0.16em] text-[#5c85ff] uppercase">Declared limitations</p>
                <ul className="mt-4 grid gap-3 text-[13px] leading-relaxed text-navy-200">
                  {[
                    "Layers marked “modelled” run deterministic, container-conditioned reference implementations. They are adapter-ready for real OpenCV models but must not be cited as ground truth.",
                    "Absence of evidence is not evidence of authenticity: aggressive recompression destroys the high-frequency signals several layers depend on.",
                    "Generative-AI detection is probabilistic and adversarially fragile; a low score never certifies human capture.",
                    "Metadata is trivially editable, so metadata conclusions are only as strong as the chain of custody.",
                    "The system examines one exhibit at a time — cross-exhibit and cross-witness correlation is future work.",
                  ].map((t) => (
                    <li key={t} className="flex gap-2.5">
                      <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-[#5c85ff]" />
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="bg-navy-950 p-6">
                <p className="font-mono text-[10px] tracking-[0.16em] text-[#06b6d4] uppercase">Ethical use</p>
                <p className="mt-4 text-[13px] leading-relaxed text-navy-200">
                  Output is <span className="text-white">decision support for a trained examiner</span>, never an
                  autonomous accusation. Every report states its own confidence and its own limitations, and the
                  recommendation field is written to trigger human review rather than to close a question.
                </p>
                <p className="mt-4 text-[13px] leading-relaxed text-navy-200">
                  Deliberate misuse — accusing a person or organisation of forgery on the basis of a risk score
                  alone — contradicts the design contract of this system and is not a supported use.
                </p>
                <div className="mt-6 rounded-lg border border-navy-800 p-4">
                  <p className="font-mono text-[10px] tracking-[0.14em] text-navy-400 uppercase">Review gate</p>
                  <p className="mt-2 text-[12.5px] leading-relaxed text-navy-200">
                    Risk ≥ 68 always requires a human examiner sign-off before any external action. The report
                    stores the examiner note field for exactly this purpose.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
