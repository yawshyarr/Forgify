"use client";

import { useMemo, useState } from "react";
import { Chip, KeyValue, Meter, Reveal, RiskGauge, StatTile } from "@/components/ui/kit";
import { RegionCanvas, RegionLegend } from "@/components/shared/RegionCanvas";
import { LAYER_ACCENT, SEVERITY_STYLE, fmtBytes, fmtDate, riskBand, shortHash } from "@/lib/format";
import type { AnalysisReport, Finding } from "@/lib/forensics/types";

const TABS = ["overview", "layers", "regions", "ocr", "metadata", "pipeline", "json"] as const;
type Tab = (typeof TABS)[number];

const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview",
  layers: "Layer results",
  regions: "Suspicious regions",
  ocr: "OCR & text",
  metadata: "Metadata",
  pipeline: "Pipeline trace",
  json: "Report JSON",
};

function severityStyle(sev: string) {
  return SEVERITY_STYLE[sev] ?? SEVERITY_STYLE.info;
}

function FindingCard({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const s = severityStyle(finding.severity);
  const accent = LAYER_ACCENT[finding.layer] ?? "#1a3ff5";
  return (
    <article
      className="overflow-hidden rounded-xl border border-hairline bg-white transition-all duration-200"
      style={{ borderColor: open ? s.border : "#e2e8f2" }}
    >
      <button type="button" onClick={() => setOpen((v) => !v)} className="w-full px-4 py-3.5 text-left">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className="rounded px-1.5 py-0.5 font-mono text-[9.5px] tracking-[0.1em] uppercase"
            style={{ background: s.bg, color: s.color }}
          >
            {s.label}
          </span>
          <span className="font-mono text-[10px] tracking-[0.08em] text-graphite-500 uppercase">{finding.code}</span>
          <span className="flex items-center gap-1.5 text-navy-200">
            <span className="h-1 w-1 rounded-full" style={{ background: accent }} />
            <span className="font-mono text-[10px] text-navy-700">{finding.layer}</span>
          </span>
          <span className="tabular ml-auto font-mono text-[10.5px] text-graphite-500">
            conf {(finding.confidence * 100).toFixed(0)}%
          </span>
          <svg
            viewBox="0 0 16 16"
            className={`h-3.5 w-3.5 shrink-0 text-graphite-500 transition-transform ${open ? "rotate-180" : ""}`}
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
          >
            <path d="M4 6l4 4 4-4" />
          </svg>
        </div>
        <h4 className="mt-2 text-[13.5px] leading-snug font-medium text-navy-950">{finding.title}</h4>
        {!open && finding.metric ? <p className="mt-1 font-mono text-[10.5px] text-graphite-500">{finding.metric}</p> : null}
      </button>
      {open ? (
        <div className="border-t border-hairline bg-surface/70 px-4 py-4">
          <p className="text-[13px] leading-relaxed text-graphite-500">{finding.description}</p>
          {finding.evidence.length ? (
            <dl className="mt-3.5 grid gap-px overflow-hidden rounded-lg border border-hairline bg-hairline sm:grid-cols-2">
              {finding.evidence.map((e) => (
                <div key={`${e.label}-${e.value}`} className="flex items-baseline justify-between gap-3 bg-white px-3 py-2">
                  <dt className="font-mono text-[9.5px] tracking-[0.08em] text-graphite-500 uppercase">{e.label}</dt>
                  <dd className="tabular truncate pl-2 font-mono text-[11.5px] text-navy-900">{e.value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
          {finding.region ? (
            <p className="mt-3 rounded-lg border border-hairline bg-white px-3 py-2 font-mono text-[10.5px] text-graphite-500">
              region · x {finding.region.x.toFixed(3)} · y {finding.region.y.toFixed(3)} · w {finding.region.width.toFixed(3)} · h{" "}
              {finding.region.height.toFixed(3)}
            </p>
          ) : null}
          {finding.recommendation ? (
            <p className="mt-3 rounded-lg border border-navy-100 bg-navy-50 px-3 py-2.5 text-[12.5px] leading-relaxed text-navy-800">
              <span className="font-mono text-[10px] tracking-[0.1em] text-electric-600 uppercase">recommended action · </span>
              {finding.recommendation}
            </p>
          ) : null}
        </div>
      ) : null}
    </article>
  );
}

type MetadataEntry = AnalysisReport["metadata"][number];

export function ReportDashboard({
  report,
  assetUrl,
  readonly = false,
}: {
  report: AnalysisReport;
  assetUrl?: string | null;
  readonly?: boolean;
}) {
  const [tab, setTab] = useState<Tab>("overview");
  const band = riskBand(report.verdict.riskScore);
  const sortedLayers = useMemo(() => [...report.layers].sort((a, b) => b.score - a.score), [report.layers]);
  const orderedFindings = useMemo(() => {
    const order = ["critical", "high", "medium", "low", "info", "benign"];
    return [...report.findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  }, [report.findings]);

  function download() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.caseCode || "forgify"}-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const metaGroups = useMemo(() => {
    const groups = new Map<string, MetadataEntry[]>();
    report.metadata.forEach((m) => {
      const list = groups.get(m.group) ?? [];
      list.push(m);
      groups.set(m.group, list);
    });
    return [...groups.entries()];
  }, [report.metadata]);

  return (
    <div className="grid gap-5">
      <div className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-hairline px-5 py-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className="rounded-md px-2 py-1 font-mono text-[10.5px] tracking-[0.1em] uppercase"
                style={{ background: band.bg, color: band.color, border: `1px solid ${band.border}` }}
              >
                {band.label}
              </span>
              <span className="font-mono text-[12px] tracking-[0.08em] text-navy-950">{report.caseCode || "UNREGISTERED"}</span>
              {report.engine.backend === "python-fastapi" ? (
                <Chip tone="cyan">python worker</Chip>
              ) : (
                <Chip tone="outline">reference runtime</Chip>
              )}
              {readonly ? <Chip tone="neutral">archived case</Chip> : null}
            </div>
            <h2 className="mt-2.5 truncate text-[17px] font-semibold tracking-[-0.02em] text-navy-950">{report.file.name}</h2>
            <p className="mt-1 font-mono text-[10.5px] text-graphite-500">
              {fmtBytes(report.file.sizeBytes)} · {report.container.detectedType}
              {report.file.dimensions ? ` · ${report.file.dimensions}` : ""}
              {report.file.pages ? ` · ${report.file.pages} page(s)` : ""} · analysed {fmtDate(report.createdAt)} · {report.durationMs} ms
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={download}
              className="inline-flex items-center gap-2 rounded-lg border border-hairline px-3 py-2 text-[12.5px] font-medium text-graphite-700 transition-colors hover:border-navy-300 hover:text-navy-950"
            >
              <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" fill="none" stroke="currentColor" strokeWidth="1.6">
                <path d="M8 2v8M4.5 7l3.5 3.5L11.5 7M3 13h10" />
              </svg>
              Export JSON
            </button>
          </div>
        </div>

        <div className="grid gap-px bg-hairline lg:grid-cols-[260px_1fr]">
          <div className="flex flex-col items-center justify-center bg-white px-5 py-6">
            <RiskGauge value={report.verdict.riskScore} confidence={report.verdict.confidence} size={200} />
            <p className="mt-3 text-center font-mono text-[10px] leading-relaxed tracking-[0.1em] text-graphite-500 uppercase">
              weighted opinion pool
            </p>
          </div>
          <div className="bg-white px-5 py-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <StatTile label="Findings" value={report.findings.length} sub={`${report.fusion.alertCount} high / critical`} />
              <StatTile label="Regions" value={report.regions.length} sub="localised" />
              <StatTile
                label="Layers run"
                value={`${report.engine.modulesExecuted}/${report.engine.modulesRegistered}`}
                sub={`${report.durationMs} ms total`}
              />
              <StatTile
                label="Agreement"
                value={report.fusion.agreement.toFixed(2)}
                sub="layer consensus"
                accent={report.fusion.agreement > 0.7 ? "#0f6b4f" : "#b54708"}
              />
            </div>

            <div className="mt-5 grid gap-4 lg:grid-cols-2">
              <div>
                <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Layer scores</p>
                <ul className="mt-2.5 grid gap-1.5">
                  {sortedLayers.slice(0, 6).map((l) => (
                    <li key={l.layer}>
                      <div className="flex items-center justify-between gap-3">
                        <span className="truncate text-[12px] text-navy-900">{l.name}</span>
                        <span
                          className="tabular shrink-0 font-mono text-[10.5px]"
                          style={{ color: l.score >= 0.5 ? "#b42318" : l.score >= 0.28 ? "#b54708" : "#43536a" }}
                        >
                          {(l.score * 100).toFixed(0)}
                        </span>
                      </div>
                      <div className="mt-1">
                        <Meter value={l.score} color={LAYER_ACCENT[l.layer] ?? "#1a3ff5"} height={3} animate={false} />
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="rounded-xl border border-hairline bg-surface/70 p-4">
                <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Recommendation</p>
                <p className="mt-2 text-[12.5px] leading-relaxed text-navy-800">{report.verdict.recommendation}</p>
                <p className="mt-3 border-t border-hairline pt-2.5 font-mono text-[10px] leading-relaxed text-graphite-500">
                  {report.verdict.chainOfCustody}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="no-scrollbar -mx-1 flex gap-1 overflow-x-auto px-1">
        {TABS.map((t) => {
          const active = t === tab;
          const count =
            t === "layers"
              ? report.layers.length
              : t === "regions"
                ? report.regions.length
                : t === "ocr"
                  ? report.ocr.blocks.length
                  : t === "metadata"
                    ? report.metadata.length
                    : t === "pipeline"
                      ? report.pipeline.length
                      : undefined;
          return (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`shrink-0 rounded-lg border px-3.5 py-2 text-[12.5px] font-medium transition-all ${
                active
                  ? "border-navy-950 bg-navy-950 text-white"
                  : "border-hairline bg-white text-graphite-700 hover:border-navy-300 hover:text-navy-950"
              }`}
            >
              {TAB_LABEL[t]}
              {count !== undefined ? (
                <span className={`ml-1.5 font-mono text-[10px] ${active ? "text-navy-300" : "text-graphite-500"}`}>{count}</span>
              ) : null}
            </button>
          );
        })}
      </div>

      {tab === "overview" ? (
        <div className="grid gap-5 lg:grid-cols-[1.25fr_0.75fr]">
          <div className="grid gap-3">
            <div className="flex items-center justify-between">
              <p className="font-mono text-[10.5px] tracking-[0.14em] text-graphite-500 uppercase">Findings · ordered by severity</p>
              <span className="font-mono text-[10.5px] text-graphite-500">{orderedFindings.length} total</span>
            </div>
            {orderedFindings.map((f, i) => (
              <FindingCard key={f.id} finding={f} defaultOpen={i === 0} />
            ))}
          </div>

          <div className="grid content-start gap-4">
            <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
              <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Evidence integrity</p>
              <div className="mt-3">
                <KeyValue
                  dense
                  items={[
                    { label: "SHA-256", value: <span title={report.hashes.sha256}>{shortHash(report.hashes.sha256, 16)}</span> },
                    { label: "SHA-1", value: <span title={report.hashes.sha1}>{shortHash(report.hashes.sha1, 12)}</span> },
                    { label: "MD5", value: <span title={report.hashes.md5}>{shortHash(report.hashes.md5, 12)}</span> },
                    { label: "Fingerprint", value: report.hashes.blurHashFingerprint.slice(0, 16) },
                    { label: "Byte entropy", value: `${report.hashes.byteEntropy} b/B` },
                  ]}
                />
              </div>
            </div>

            <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
              <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Fusion rationale</p>
              <ul className="mt-3 grid gap-2.5">
                {report.fusion.rationale.map((r) => (
                  <li key={r} className="flex gap-2.5 text-[12.5px] leading-relaxed text-graphite-500">
                    <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-electric-500" />
                    {r}
                  </li>
                ))}
              </ul>
              <div className="mt-4 border-t border-hairline pt-3">
                <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Examination mode</p>
                <p className="mt-2 text-[12.5px] text-navy-800">{report.reference.mode}</p>
                <ul className="mt-2 grid gap-1.5">
                  {report.reference.deltaNotes.slice(0, 4).map((n) => (
                    <li key={n} className="font-mono text-[10.5px] leading-relaxed text-graphite-500">
                      · {n}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="rounded-2xl border border-hairline bg-navy-950 p-5">
              <p className="font-mono text-[10px] tracking-[0.14em] text-[#5c85ff] uppercase">Container observations</p>
              <ul className="mt-3 grid gap-2">
                {report.container.containerNotes.map((n) => (
                  <li key={n} className="flex gap-2 text-[12px] leading-relaxed text-navy-200">
                    <span className="mt-[6px] h-1 w-1 shrink-0 rounded-full bg-[#06b6d4]" />
                    {n}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      ) : null}

      {tab === "layers" ? (
        <div className="grid gap-3">
          {sortedLayers.map((layer) => {
            const accent = LAYER_ACCENT[layer.layer] ?? "#1a3ff5";
            const tone =
              layer.status === "alert"
                ? SEVERITY_STYLE.high
                : layer.status === "review"
                  ? SEVERITY_STYLE.medium
                  : SEVERITY_STYLE.benign;
            return (
              <article key={layer.layer} className="overflow-hidden rounded-xl border border-hairline bg-white shadow-[var(--shadow-card)]">
                <div className="flex flex-wrap items-start justify-between gap-4 border-b border-hairline px-5 py-4">
                  <div className="flex min-w-0 items-start gap-3.5">
                    <span
                      className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg font-mono text-[10px] font-semibold text-white"
                      style={{ background: accent }}
                    >
                      {layer.layer.slice(0, 2).toUpperCase()}
                    </span>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-[14.5px] font-semibold tracking-[-0.015em] text-navy-950">{layer.name}</h3>
                        <span
                          className="rounded px-1.5 py-0.5 font-mono text-[9.5px] tracking-[0.1em] uppercase"
                          style={{ background: tone.bg, color: tone.color }}
                        >
                          {layer.status}
                        </span>
                        <Chip tone={layer.mode === "live" ? "live" : "neutral"}>{layer.mode}</Chip>
                      </div>
                      <p className="mt-1.5 text-[12.5px] leading-relaxed text-graphite-500">{layer.summary}</p>
                      <p className="mt-1.5 font-mono text-[10px] text-graphite-500">
                        {layer.runtime} · {layer.durationMs} ms · weight {layer.weight.toFixed(2)}
                      </p>
                    </div>
                  </div>
                  <div className="w-40 shrink-0">
                    <div className="flex items-baseline justify-between">
                      <span className="font-mono text-[9.5px] tracking-[0.1em] text-graphite-500 uppercase">score</span>
                      <span className="tabular font-mono text-[16px] font-semibold" style={{ color: tone.color }}>
                        {(layer.score * 100).toFixed(0)}
                      </span>
                    </div>
                    <div className="mt-1.5">
                      <Meter value={layer.score} color={tone.color} height={5} animate={false} />
                    </div>
                    <p className="mt-1.5 text-right font-mono text-[10px] text-graphite-500">
                      conf {(layer.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
                <div className="grid gap-3 px-5 py-4 lg:grid-cols-[1.4fr_0.6fr]">
                  <div className="grid gap-2">
                    {layer.findings.length ? (
                      layer.findings.map((f) => <FindingCard key={f.id} finding={f} />)
                    ) : (
                      <p className="rounded-lg border border-dashed border-hairline px-4 py-4 text-center text-[12.5px] text-graphite-500">
                        No findings raised by this layer.
                      </p>
                    )}
                  </div>
                  <div className="rounded-xl border border-hairline bg-surface/70 p-4">
                    <p className="font-mono text-[10px] tracking-[0.12em] text-graphite-500 uppercase">Metrics</p>
                    <div className="mt-2.5">
                      <KeyValue dense items={layer.metrics.map((m) => ({ label: m.label, value: m.value }))} />
                    </div>
                    <p className="mt-3 border-t border-hairline pt-2.5 font-mono text-[9.5px] tracking-[0.1em] text-graphite-500 uppercase">
                      techniques
                    </p>
                    <ul className="mt-1.5 grid gap-1">
                      {layer.techniques.map((t) => (
                        <li key={t} className="font-mono text-[10.5px] text-graphite-500">
                          · {t}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </article>
            );
          })}
        </div>
      ) : null}

      {tab === "regions" ? (
        <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-2xl border border-hairline bg-white p-4 shadow-[var(--shadow-card)]">
            <RegionCanvas
              regions={report.regions}
              imageUrl={assetUrl ?? null}
              aspect={report.file.kind === "pdf" ? 1 / 1.414 : 1.5}
              renderSurface={
                assetUrl
                  ? undefined
                  : () => (
                      <div className="hairline-grid absolute inset-0 flex flex-col items-center justify-center gap-3 bg-surface p-6 text-center">
                        <p className="font-mono text-[10.5px] tracking-[0.14em] text-graphite-500 uppercase">
                          {report.file.kind === "pdf" ? "PDF page geometry" : "raster preview not stored"}
                        </p>
                        <p className="max-w-[75%] text-[12px] leading-relaxed text-graphite-500">
                          Region coordinates are normalised to the exhibit frame, so they map directly onto the
                          original pages even when no raster preview is persisted.
                        </p>
                        <div className="mt-1 w-full max-w-[75%] rounded-lg border border-hairline bg-white p-4">
                          {report.ocr.blocks.slice(0, 9).map((b) => (
                            <div key={b.index} className="flex items-center gap-2 py-[3px]">
                              <span className="h-[3px] rounded-full bg-navy-200" style={{ width: `${18 + (b.index % 4) * 9}%` }} />
                              <span className="tabular font-mono text-[9px] text-graphite-500">{(b.confidence * 100).toFixed(0)}%</span>
                              {b.anomalies.length ? <span className="h-1.5 w-1.5 rounded-full bg-[#b42318]" /> : null}
                            </div>
                          ))}
                        </div>
                      </div>
                    )
              }
            />
          </div>
          <div>
            <RegionLegend regions={report.regions} />
          </div>
        </div>
      ) : null}

      {tab === "ocr" ? (
        <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Recovered text layer</p>
              <div className="flex flex-wrap gap-2">
                <Chip tone="outline">{report.ocr.wordCount} words</Chip>
                <Chip tone="outline">mean conf {(report.ocr.meanConfidence * 100).toFixed(1)}%</Chip>
                <Chip tone={report.ocr.mode === "live" ? "live" : "neutral"}>{report.ocr.mode}</Chip>
              </div>
            </div>
            <div className="mt-4 grid gap-1.5">
              {report.ocr.blocks.map((b) => {
                const flagged = b.anomalies.length > 0;
                return (
                  <div
                    key={b.index}
                    className="flex items-start gap-3 rounded-lg border px-3 py-2"
                    style={{
                      borderColor: flagged ? SEVERITY_STYLE.high.border : "#e2e8f2",
                      background: flagged ? SEVERITY_STYLE.high.bg : "#fff",
                    }}
                  >
                    <span className="tabular w-6 shrink-0 font-mono text-[10px] text-graphite-500">
                      {String(b.index).padStart(2, "0")}
                    </span>
                    <p className="min-w-0 flex-1 font-mono text-[11.5px] leading-relaxed break-words text-navy-900">{b.text}</p>
                    <span className="tabular shrink-0 font-mono text-[10px]" style={{ color: b.confidence < 0.8 ? "#b42318" : "#55637a" }}>
                      {(b.confidence * 100).toFixed(0)}%
                    </span>
                    {flagged ? (
                      <span className="shrink-0 font-mono text-[9px] tracking-[0.08em] text-[#b42318] uppercase">{b.anomalies[0]}</span>
                    ) : null}
                  </div>
                );
              })}
            </div>
          </div>
          <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
            <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Detector</p>
            <div className="mt-3">
              <KeyValue
                dense
                items={[
                  { label: "Engine", value: report.ocr.engine },
                  { label: "Mode", value: report.ocr.mode },
                  { label: "Language", value: report.ocr.language },
                  { label: "Blocks", value: report.ocr.blocks.length },
                  { label: "Low confidence", value: report.ocr.blocks.filter((b) => b.confidence < 0.8).length },
                  { label: "Anomalous", value: report.ocr.blocks.filter((b) => b.anomalies.length).length },
                ]}
              />
            </div>
            <p className="mt-4 rounded-lg border border-hairline bg-surface/70 px-3.5 py-3 text-[12px] leading-relaxed text-graphite-500">
              Blocks flagged by the glyph model are highlighted. In a printed digital document, low recognition
              confidence usually means those glyphs were rasterised from a different source than the rest of the page.
            </p>
          </div>
        </div>
      ) : null}

      {tab === "metadata" ? (
        <div className="grid gap-4 md:grid-cols-2">
          {metaGroups.map(([group, entries]) => (
            <div key={group} className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
              <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">{group}</p>
              <dl className="mt-3 divide-y divide-hairline">
                {entries.map((m) => {
                  const flagTone =
                    m.flag === "tamper" ? "#b42318" : m.flag === "missing" ? "#b54708" : m.flag === "info" ? "#3a66a0" : "#43536a";
                  return (
                    <div key={`${m.group}-${m.key}`} className="flex items-start justify-between gap-4 py-2.5">
                      <dt className="flex min-w-0 items-start gap-2">
                        {m.flag && m.flag !== "ok" ? (
                          <span className="mt-[6px] h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: flagTone }} />
                        ) : null}
                        <span className="font-mono text-[11px] text-graphite-500">{m.key}</span>
                      </dt>
                      <dd className="max-w-[62%] text-right">
                        <span className="block font-mono text-[11.5px] break-words text-navy-900">{m.value}</span>
                        <span
                          className="mt-0.5 block font-mono text-[9px] tracking-[0.08em] uppercase"
                          style={{ color: flagTone }}
                        >
                          {m.flag && m.flag !== "ok" ? m.flag : m.source}
                        </span>
                      </dd>
                    </div>
                  );
                })}
              </dl>
            </div>
          ))}
        </div>
      ) : null}

      {tab === "pipeline" ? (
        <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Eight-stage pipeline trace</p>
            <Chip tone="outline">total {report.durationMs} ms</Chip>
          </div>
          <ol className="mt-5 grid gap-px overflow-hidden rounded-xl border border-hairline bg-hairline">
            {report.pipeline.map((step) => {
              const tone =
                step.status === "alert"
                  ? SEVERITY_STYLE.high
                  : step.status === "warn"
                    ? SEVERITY_STYLE.medium
                    : SEVERITY_STYLE.benign;
              return (
                <li key={step.key} className="flex items-start gap-4 bg-white px-4 py-3.5">
                  <span className="tabular mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-hairline bg-navy-50 font-mono text-[10px] text-graphite-500">
                    {String(step.step).padStart(2, "0")}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h4 className="text-[13.5px] font-medium text-navy-950">{step.label}</h4>
                      <span
                        className="rounded px-1.5 py-0.5 font-mono text-[9px] tracking-[0.1em] uppercase"
                        style={{ background: tone.bg, color: tone.color }}
                      >
                        {step.status}
                      </span>
                      <span className="tabular ml-auto font-mono text-[10px] text-graphite-500">{step.durationMs} ms</span>
                    </div>
                    <p className="mt-1 font-mono text-[11px] leading-relaxed break-words text-graphite-500">{step.detail}</p>
                  </div>
                </li>
              );
            })}
          </ol>
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <div className="rounded-xl border border-hairline bg-surface/70 p-4">
              <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Engine</p>
              <div className="mt-2">
                <KeyValue
                  dense
                  items={[
                    { label: "Name", value: report.engine.name },
                    { label: "Version", value: report.engine.version },
                    { label: "Backend", value: report.engine.backend },
                    { label: "Modules", value: `${report.engine.modulesExecuted}/${report.engine.modulesRegistered}` },
                  ]}
                />
              </div>
            </div>
            <div className="rounded-xl border border-hairline bg-surface/70 p-4">
              <p className="font-mono text-[10px] tracking-[0.14em] text-graphite-500 uppercase">Declared limitations</p>
              <ul className="mt-2 grid gap-1.5">
                {report.limitations.map((l) => (
                  <li key={l} className="text-[11.5px] leading-relaxed text-graphite-500">
                    · {l}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      ) : null}

      {tab === "json" ? (
        <div className="overflow-hidden rounded-2xl border border-hairline bg-navy-950">
          <div className="flex items-center justify-between border-b border-navy-900 px-5 py-3">
            <p className="font-mono text-[10.5px] tracking-[0.14em] text-navy-300 uppercase">
              GET /api/analyses/{report.id || "{caseId}"}
            </p>
            <button
              type="button"
              onClick={download}
              className="rounded-md border border-navy-800 px-2.5 py-1 font-mono text-[10px] tracking-[0.1em] text-navy-200 uppercase transition-colors hover:border-electric-500 hover:text-white"
            >
              download
            </button>
          </div>
          <pre className="no-scrollbar max-h-[640px] overflow-auto px-5 py-4 font-mono text-[11px] leading-relaxed text-navy-100">
            {JSON.stringify(report, null, 2)}
          </pre>
        </div>
      ) : null}

      {tab === "overview" ? (
        <Reveal>
          <p className="rounded-xl border border-dashed border-hairline px-5 py-4 text-[12px] leading-relaxed text-graphite-500">
            <span className="font-mono text-[10px] tracking-[0.12em] text-graphite-500 uppercase">
              Read this before citing the result ·{" "}
            </span>
            {report.limitations[0]}
          </p>
        </Reveal>
      ) : null}
    </div>
  );
}
