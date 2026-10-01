"use client";

import { useMemo, useState } from "react";
import { Chip, Meter, Reveal, RiskGauge, SectionHeading } from "@/components/ui/kit";
import { RegionCanvas, RegionLegend, type RegionLike } from "@/components/shared/RegionCanvas";
import { LAYERS } from "@/lib/forensics/registry";

/* ======================= 6 · EVIDENCE FUSION VISUAL ====================== */

const FUSION_INPUT = LAYERS.map((l, i) => {
  const demoScores = [0.87, 0.34, 0.58, 0.31, 0.72, 0.44, 0.81, 0.63, 0.19, 0.91, 0.66];
  return { ...l, demo: demoScores[i] ?? 0.3 };
});

export function EvidenceFusion() {
  const [hover, setHover] = useState<string | null>(null);

  const rows = useMemo(() => {
    const raw = FUSION_INPUT.map((l) => ({ layer: l.id, name: l.name, weight: l.weight, score: l.demo, contribution: l.weight * l.demo, accent: l.accent, short: l.short, status: l.demo >= 0.5 ? "alert" : l.demo >= 0.28 ? "review" : "pass" }));
    const total = raw.reduce((a, r) => a + r.contribution, 0);
    return raw.map((r) => ({ ...r, share: r.contribution / total })).sort((a, b) => b.contribution - a.contribution);
  }, []);

  const fusedMass = rows.reduce((a, r) => a + r.contribution, 0);
  const risk = Math.round((1 / (1 + Math.exp(-5.2 * (fusedMass / 1.17 - 0.45)))) * 100);
  const highlight = hover;

  return (
    <section id="fusion" className="border-b border-hairline bg-surface py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Evidence fusion"
            title="Many weak signals become one defensible decision"
            lead="Each layer votes with a suspicion score and a confidence. The fusion stage multiplies them, normalises the weights and calibrates the result — recording exactly how much of the decision each layer contributed."
          />
        </Reveal>

        <div className="mt-12 grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <Reveal>
            <div className="rounded-2xl border border-hairline bg-white p-6 shadow-[var(--shadow-card)]">
              <div className="flex items-center justify-between">
                <p className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">Signal convergence</p>
                <Chip tone="outline">linear opinion pool</Chip>
              </div>

              <svg viewBox="0 0 560 380" className="mt-4 w-full" role="img" aria-label="Eleven detector signals converging into a fused decision">
                {/* incoming rails */}
                {FUSION_INPUT.map((l, i) => {
                  const y = 22 + i * 31;
                  const active = highlight === l.id;
                  const alert = l.demo >= 0.5;
                  return (
                    <g
                      key={l.id}
                      onMouseEnter={() => setHover(l.id)}
                      onMouseLeave={() => setHover(null)}
                      style={{ cursor: "pointer" }}
                    >
                      <rect x={0} y={y - 11} width={150} height={22} rx={5} fill={active ? "#f3f6fb" : "#ffffff"} stroke={active ? l.accent : "#e2e8f2"} />
                      <rect x={6} y={y - 6} width={14} height={12} rx={3} fill={l.accent} opacity={active ? 1 : 0.85} />
                      <text x={26} y={y + 4} fontSize={9.5} fill={active ? "#071122" : "#55637a"} fontFamily="ui-monospace, monospace">
                        {l.short}
                      </text>
                      <rect x={84} y={y - 3} width={50} height={5} rx={2.5} fill="#eaeff7" />
                      <rect x={84} y={y - 3} width={50 * l.demo} height={5} rx={2.5} fill={alert ? "#b42318" : l.accent} />
                      <text x={140} y={y + 4} fontSize={9} fill="#55637a" fontFamily="ui-monospace, monospace">
                        {(l.demo * 100).toFixed(0)}
                      </text>
                      <path
                        d={`M156 ${y} C 240 ${y}, 300 190, 372 190`}
                        fill="none"
                        stroke={alert ? "#b42318" : l.accent}
                        strokeWidth={active ? 1.8 : 0.9}
                        strokeDasharray={alert ? "none" : "3 3"}
                        opacity={highlight && !active ? 0.18 : 0.75}
                        style={{ transition: "opacity 700ms ease, stroke-width 200ms ease" }}
                      />
                    </g>
                  );
                })}

                {/* fusion node */}
                <circle cx={392} cy={190} r={20} fill="#ffffff" stroke="#071122" strokeWidth={1.5} />
                <circle cx={392} cy={190} r={28} fill="none" stroke="#1a3ff5" strokeWidth={0.8} strokeDasharray="4 4" style={{ animation: "var(--animate-dash)" }} />
                <text x={392} y={187} textAnchor="middle" fontSize={9} fill="#071122" fontFamily="ui-monospace, monospace">
                  FUSE
                </text>
                <text x={392} y={199} textAnchor="middle" fontSize={7.5} fill="#55637a" fontFamily="ui-monospace, monospace">
                  σ-weighted
                </text>

                <path d="M420 190 L470 190" stroke="#071122" strokeWidth={1.5} />
                <path d="M470 190 l-6 -4 v8 z" fill="#071122" />

                <rect x={478} y={160} width={78} height={60} rx={8} fill="#0a1f3c" />
                <text x={517} y={186} textAnchor="middle" fontSize={22} fill="#ffffff" fontFamily="ui-monospace, monospace">
                  {risk}
                </text>
                <text x={517} y={202} textAnchor="middle" fontSize={8} fill="#9db4d3" fontFamily="ui-monospace, monospace">
                  RISK / 100
                </text>
                <text x={517} y={236} textAnchor="middle" fontSize={8.5} fill="#55637a" fontFamily="ui-monospace, monospace">
                  91% confidence
                </text>
              </svg>

              <div className="mt-2 border-t border-hairline pt-4">
                <p className="text-[12.5px] leading-relaxed text-graphite-500">
                  Hover a detector to isolate its contribution. Red rails crossed the alert threshold; dashed rails
                  voted but did not move the decision. Two detectors can be individually ambiguous and still, in
                  combination, produce a decisive signal.
                </p>
              </div>
            </div>
          </Reveal>

          <Reveal delay={90}>
            <div className="flex h-full flex-col gap-4">
              <div className="rounded-2xl border border-hairline bg-white p-6 shadow-[var(--shadow-card)]">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">Fused decision</p>
                    <p className="mt-1.5 text-[13px] text-graphite-500">Calibrated, weighted, explained</p>
                  </div>
                  <Chip tone={risk >= 68 ? "alert" : "neutral"}>{risk >= 68 ? "likely forged" : risk >= 45 ? "suspicious" : "review"}</Chip>
                </div>
                <div className="mt-4 flex justify-center">
                  <RiskGauge value={risk} confidence={0.91} size={180} />
                </div>
                <dl className="mt-2 grid grid-cols-2 gap-3">
                  {[
                    ["Evidence mass", (fusedMass / 1.17).toFixed(4)],
                    ["Agreement", "0.74"],
                    ["Layers alerting", "5 / 11"],
                    ["Cross-links", "2"],
                  ].map(([k, v]) => (
                    <div key={k} className="rounded-lg border border-hairline px-3 py-2">
                      <dt className="font-mono text-[9.5px] tracking-[0.12em] text-graphite-500 uppercase">{k}</dt>
                      <dd className="tabular mt-1 font-mono text-[14px] text-navy-950">{v}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              <div className="flex-1 rounded-2xl border border-hairline bg-white p-6 shadow-[var(--shadow-card)]">
                <p className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">Contribution ranking</p>
                <ul className="mt-4 grid gap-2.5">
                  {rows.slice(0, 6).map((r) => (
                    <li
                      key={r.layer}
                      onMouseEnter={() => setHover(r.layer)}
                      onMouseLeave={() => setHover(null)}
                      className="group"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="flex items-center gap-2 truncate text-[12.5px] text-navy-900">
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: r.accent }} />
                          {r.name}
                        </span>
                        <span className="tabular shrink-0 font-mono text-[10.5px] text-graphite-500">
                          {(r.share * 100).toFixed(1)}%
                        </span>
                      </div>
                      <div className="mt-1.5">
                        <Meter value={r.share * 3.2} color={r.accent} height={4} animate={false} />
                      </div>
                    </li>
                  ))}
                </ul>
                <p className="mt-4 border-t border-hairline pt-3 font-mono text-[10px] leading-relaxed text-graphite-500">
                  Every report stores this table, so the contribution of each layer to a given verdict is
                  auditable after the fact.
                </p>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

/* =================== 7 · SUSPICIOUS REGION LOCALISATION ================== */

const DEMO_REGIONS: RegionLike[] = [
  { id: "R-01", label: "Error-level divergence", layer: "pixel", score: 0.87, confidence: 0.93, x: 0.5, y: 0.3, width: 0.33, height: 0.1, technique: "ELA + noise variance", notes: "Residual hotspot with a noise floor that breaks from the host image — the pasted region." },
  { id: "R-02", label: "Clone source patch", layer: "copy-move", score: 0.81, confidence: 0.9, x: 0.09, y: 0.53, width: 0.25, height: 0.17, technique: "SIFT cluster + RANSAC", notes: "Source of the duplicated content according to the recovered affine transform." },
  { id: "R-03", label: "Clone destination patch", layer: "copy-move", score: 0.81, confidence: 0.9, x: 0.36, y: 0.62, width: 0.22, height: 0.16, technique: "SIFT cluster + RANSAC", notes: "Destination patch sharing the same transform parameters as R-02." },
  { id: "R-04", label: "Substituted digits", layer: "ocr", score: 0.72, confidence: 0.91, x: 0.55, y: 0.44, width: 0.28, height: 0.08, technique: "Glyph stroke-width model", notes: "Amount field maps to a different font family with 2.9× stroke variance." },
  { id: "R-05", label: "Pseudo-text glyph run", layer: "aigc", score: 0.66, confidence: 0.84, x: 0.62, y: 0.68, width: 0.28, height: 0.14, technique: "Script-plausibility test", notes: "Letterforms with no valid Unicode mapping — characteristic of diffusion-rendered text." },
  { id: "R-06", label: "Signature paste halo", layer: "signature", score: 0.63, confidence: 0.8, x: 0.3, y: 0.79, width: 0.26, height: 0.11, technique: "Ink raster edge analysis", notes: "Hard 2-px boundary and residual background compression around the ink object." },
];

const DEMO_SURFACE = (
  <svg viewBox="0 0 200 283" className="absolute inset-0 h-full w-full" preserveAspectRatio="none">
    <rect x="0" y="0" width="200" height="283" fill="#ffffff" />
    <rect x="14" y="16" width="52" height="7" rx="1.5" fill="#0d2b53" />
    <rect x="14" y="28" width="34" height="3" rx="1.5" fill="#9db4d3" />
    <rect x="136" y="16" width="50" height="3" rx="1.5" fill="#c8d6ea" />
    <rect x="136" y="23" width="40" height="3" rx="1.5" fill="#c8d6ea" />
    <rect x="136" y="30" width="44" height="3" rx="1.5" fill="#c8d6ea" />
    <rect x="14" y="42" width="172" height="0.8" fill="#e2e8f2" />
    <rect x="14" y="54" width="38" height="5" rx="1.5" fill="#3a66a0" />
    {[68, 76, 84].map((y, i) => (
      <g key={y}>
        <rect x="14" y={y} width="30" height="2.6" rx="1" fill="#c8d6ea" />
        <rect x="50" y={y} width={44 + i * 6} height="2.6" rx="1" fill="#9db4d3" />
      </g>
    ))}
    <rect x="14" y="96" width="172" height="10" rx="2" fill="#f3f6fb" />
    {[112, 128, 144, 160].map((y, i) => (
      <g key={y}>
        <rect x="14" y={y} width={64 - i * 5} height="2.6" rx="1" fill="#c8d6ea" />
        <rect x="14" y={y + 5} width="42" height="2" rx="1" fill="#e4ebf5" />
        <rect x="112" y={y} width="16" height="2.6" rx="1" fill="#c8d6ea" />
        <rect x="150" y={y} width="32" height="2.6" rx="1" fill="#9db4d3" />
      </g>
    ))}
    <rect x="118" y="176" width="66" height="14" rx="2" fill="#eef4ff" />
    <rect x="124" y="181" width="20" height="3.4" rx="1" fill="#1d4a86" />
    <rect x="150" y="180" width="28" height="4.6" rx="1" fill="#0a1f3c" />
    <rect x="124" y="196" width="22" height="2.6" rx="1" fill="#c8d6ea" />
    <rect x="150" y="196" width="26" height="2.6" rx="1" fill="#9db4d3" />
    <g opacity="0.85">
      <circle cx="44" cy="222" r="16" fill="none" stroke="#1d4a86" strokeWidth="1.2" />
      <circle cx="44" cy="222" r="11.5" fill="none" stroke="#1d4a86" strokeWidth="0.7" />
      <path d="M35 220h18M35 225h13" stroke="#1d4a86" strokeWidth="1.1" />
    </g>
    <path d="M92 226c6-8 10 2 14-4s6-8 10-2 4 8 9 3 8-9 12-3" fill="none" stroke="#0a1f3c" strokeWidth="1.3" strokeLinecap="round" />
    <rect x="92" y="234" width="46" height="2" rx="1" fill="#c8d6ea" />
    <g fill="#0a1f3c">
      {Array.from({ length: 42 }).map((_, i) => {
        const col = i % 7;
        const row = Math.floor(i / 7);
        return (i * 5 + row * 3) % 4 < 2 ? <rect key={i} x={148 + col * 3} y={246 + row * 3} width="2.6" height="2.6" /> : null;
      })}
    </g>
    <rect x="14" y="248" width="120" height="2" rx="1" fill="#e4ebf5" />
    <rect x="14" y="254" width="94" height="2" rx="1" fill="#e4ebf5" />
  </svg>
);

export function RegionDemo() {
  const [selected, setSelected] = useState<string | null>("R-01");
  const [activeLayers, setActiveLayers] = useState<string[]>([]);
  const [showHeat, setShowHeat] = useState(true);

  const presentLayers = Array.from(new Set(DEMO_REGIONS.map((r) => r.layer)));
  const toggle = (id: string) =>
    setActiveLayers((prev) => (prev.includes(id) ? prev.filter((l) => l !== id) : [...prev, id]));

  return (
    <section id="regions" className="border-b border-hairline bg-white py-24">
      <div className="mx-auto max-w-7xl px-5 sm:px-8">
        <Reveal>
          <SectionHeading
            eyebrow="Suspicious region localisation"
            title="Not just a verdict — the exact pixels involved"
            lead="Every detector that can localise returns normalised coordinates. Toggle layers, click a region and read the measurement behind it. The same component renders an uploaded JPEG in the analysis workbench."
          />
        </Reveal>

        <div className="mt-12 grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <Reveal>
            <div className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-card)]">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-hairline bg-navy-50/60 px-4 py-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  {presentLayers.map((id) => {
                    const on = activeLayers.length === 0 || activeLayers.includes(id);
                    return (
                      <button
                        key={id}
                        type="button"
                        onClick={() => toggle(id)}
                        className={`rounded-md border px-2 py-1 font-mono text-[10px] tracking-[0.08em] uppercase transition-all ${
                          on ? "border-navy-200 bg-white text-navy-900" : "border-hairline bg-transparent text-navy-300"
                        }`}
                      >
                        {id}
                      </button>
                    );
                  })}
                </div>
                <button
                  type="button"
                  onClick={() => setShowHeat((v) => !v)}
                  className={`rounded-md border px-2 py-1 font-mono text-[10px] tracking-[0.08em] uppercase transition-colors ${
                    showHeat ? "border-electric-300 bg-electric-50 text-electric-600" : "border-hairline text-graphite-500"
                  }`}
                >
                  heatmap {showHeat ? "on" : "off"}
                </button>
              </div>
              <div className="bg-surface p-4">
                <RegionCanvas
                  regions={DEMO_REGIONS}
                  aspect={1 / 1.414}
                  selectedId={selected}
                  onSelect={setSelected}
                  activeLayers={activeLayers}
                  showHeat={showHeat}
                  renderSurface={() => DEMO_SURFACE}
                />
                <p className="mt-3 font-mono text-[10px] leading-relaxed text-graphite-500">
                  6 regions · normalised 0–1 coordinates · {activeLayers.length ? `${activeLayers.length} layer(s) isolated` : "all layers shown"} · click to inspect
                </p>
              </div>
            </div>
          </Reveal>

          <Reveal delay={90}>
            <div className="flex h-full flex-col gap-4">
              <div className="rounded-2xl border border-hairline bg-white p-5 shadow-[var(--shadow-card)]">
                <p className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">Region evidence</p>
                <div className="mt-4">
                  <RegionLegend regions={DEMO_REGIONS} selectedId={selected} onSelect={setSelected} />
                </div>
              </div>
              <div className="rounded-2xl border border-hairline bg-navy-950 p-5">
                <p className="font-mono text-[10px] tracking-[0.16em] text-[#5c85ff] uppercase">Cross-layer check</p>
                <p className="mt-3 text-[13px] leading-relaxed text-navy-200">
                  The fusion stage compares all region pairs by IoU. When two methodologically independent
                  detectors overlap, a corroboration finding is promoted — it is the strongest evidence class the
                  system produces.
                </p>
                <div className="mt-4 grid gap-2">
                  {[
                    ["R-01 pixel ⇄ R-04 ocr", "IoU 0.42", "#b42318"],
                    ["R-02 ⇄ R-03 copy-move", "affine match", "#b42318"],
                    ["R-05 aigc ⇄ R-06 signature", "no overlap", "#55637a"],
                  ].map(([pair, result, tone]) => (
                    <div key={pair} className="flex items-center justify-between rounded-lg border border-navy-800 px-3 py-2">
                      <span className="font-mono text-[10.5px] text-navy-200">{pair}</span>
                      <span className="font-mono text-[10.5px]" style={{ color: tone }}>
                        {result}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
