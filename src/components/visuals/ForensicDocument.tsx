"use client";

import { useEffect, useState } from "react";
import { Chip } from "@/components/ui/kit";

interface Hotspot {
  id: string;
  layer: string;
  layerLabel: string;
  label: string;
  metric: string;
  score: number;
  box: { x: number; y: number; w: number; h: number };
  color: string;
  band: string;
}

const HOTSPOTS: Hotspot[] = [
  {
    id: "px",
    layer: "pixel",
    layerLabel: "Pixel integrity",
    label: "Error-level divergence",
    metric: "ΔELA 11.4 dB",
    score: 0.87,
    box: { x: 0.5, y: 0.31, w: 0.32, h: 0.09 },
    color: "#1a3ff5",
    band: "Critical",
  },
  {
    id: "cm",
    layer: "copy-move",
    layerLabel: "Copy-move",
    label: "Clone pair (affine match)",
    metric: "184 inliers",
    score: 0.81,
    box: { x: 0.1, y: 0.55, w: 0.24, h: 0.15 },
    color: "#1630d8",
    band: "High",
  },
  {
    id: "oc",
    layer: "ocr",
    layerLabel: "OCR & glyphs",
    label: "Substituted digits",
    metric: "2.9× stroke var",
    score: 0.72,
    box: { x: 0.56, y: 0.44, w: 0.26, h: 0.07 },
    color: "#133a6f",
    band: "High",
  },
  {
    id: "ai",
    layer: "aigc",
    layerLabel: "Generative-AI",
    label: "Pseudo-text glyph run",
    metric: "6 unmapped runs",
    score: 0.66,
    box: { x: 0.62, y: 0.68, w: 0.28, h: 0.13 },
    color: "#071122",
    band: "Medium",
  },
  {
    id: "md",
    layer: "metadata",
    layerLabel: "Metadata",
    label: "Timestamp paradox",
    metric: "−412 min",
    score: 0.58,
    box: { x: 0.08, y: 0.16, w: 0.36, h: 0.08 },
    color: "#06b6d4",
    band: "Medium",
  },
];

const RAIL = [
  { id: "pixel", code: "PX", name: "Pixel", score: 0.87 },
  { id: "compression", code: "CQ", name: "Compression", score: 0.34 },
  { id: "metadata", code: "MD", name: "Metadata", score: 0.58 },
  { id: "provenance", code: "PR", name: "Provenance", score: 0.31 },
  { id: "ocr", code: "OC", name: "OCR", score: 0.72 },
  { id: "layout", code: "LY", name: "Layout", score: 0.44 },
  { id: "copy-move", code: "CM", name: "Copy-move", score: 0.81 },
  { id: "signature", code: "SG", name: "Signature", score: 0.63 },
  { id: "qr-barcode", code: "QR", name: "QR", score: 0.19 },
  { id: "semantic", code: "SE", name: "Semantic", score: 0.91 },
  { id: "aigc", code: "AI", name: "AIGC", score: 0.66 },
];

export function ForensicDocument() {
  const [active, setActive] = useState(0);

  useEffect(() => {
    const t = setInterval(() => setActive((v) => (v + 1) % HOTSPOTS.length), 2800);
    return () => clearInterval(t);
  }, []);

  const current = HOTSPOTS[active];

  return (
    <div className="relative">
      {/* exhibit frame */}
      <div className="overflow-hidden rounded-2xl border border-hairline bg-white shadow-[var(--shadow-lift)]">
        <div className="flex items-center justify-between gap-3 border-b border-hairline bg-navy-50/60 px-4 py-3">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-navy-950 font-mono text-[9px] text-white">PDF</span>
            <div className="min-w-0">
              <p className="truncate text-[12.5px] font-medium text-navy-950">tax_invoice_INV-48213.pdf</p>
              <p className="font-mono text-[10px] tracking-[0.08em] text-graphite-500 uppercase">
                SHA-256 4f2a…9be1 · 812 KB · 1 page
              </p>
            </div>
          </div>
          <Chip tone="alert">risk 78 / 100</Chip>
        </div>

        <div className="grid gap-0 sm:grid-cols-[1.55fr_1fr]">
          {/* document surface */}
          <div className="relative border-b border-hairline bg-surface p-4 sm:border-r sm:border-b-0">
            <div className="relative overflow-hidden rounded-lg border border-hairline bg-white" style={{ aspectRatio: "1 / 1.414" }}>
              <svg viewBox="0 0 200 283" className="absolute inset-0 h-full w-full">
                <g fill="#ffffff">
                  <rect x="0" y="0" width="200" height="283" />
                </g>
                {/* letterhead */}
                <rect x="16" y="18" width="46" height="7" rx="1.5" fill="#0d2b53" opacity="0.92" />
                <rect x="16" y="29" width="30" height="3" rx="1.5" fill="#9db4d3" />
                <rect x="140" y="18" width="44" height="3" rx="1.5" fill="#c8d6ea" />
                <rect x="140" y="25" width="34" height="3" rx="1.5" fill="#c8d6ea" />
                <rect x="140" y="32" width="38" height="3" rx="1.5" fill="#c8d6ea" />
                <rect x="16" y="44" width="168" height="0.8" fill="#e2e8f2" />

                {/* title */}
                <rect x="16" y="54" width="34" height="5" rx="1.5" fill="#3a66a0" />
                {/* meta block (metadata hotspot) */}
                <rect x="16" y="66" width="30" height="2.6" rx="1" fill="#c8d6ea" />
                <rect x="50" y="66" width="44" height="2.6" rx="1" fill="#9db4d3" />
                <rect x="16" y="72" width="26" height="2.6" rx="1" fill="#c8d6ea" />
                <rect x="50" y="72" width="38" height="2.6" rx="1" fill="#9db4d3" />

                {/* table header */}
                <rect x="16" y="88" width="168" height="10" rx="2" fill="#f3f6fb" />
                <rect x="21" y="92" width="14" height="2.4" rx="1" fill="#9db4d3" />
                <rect x="70" y="92" width="20" height="2.4" rx="1" fill="#9db4d3" />
                <rect x="130" y="92" width="20" height="2.4" rx="1" fill="#9db4d3" />

                {/* line items */}
                {[106, 122, 138, 154].map((y, i) => (
                  <g key={y}>
                    <rect x="16" y={y} width={62 - i * 4} height="2.6" rx="1" fill="#c8d6ea" />
                    <rect x="16" y={y + 5} width={40} height="2" rx="1" fill="#e4ebf5" />
                    <rect x="110" y={y} width="16" height="2.6" rx="1" fill="#c8d6ea" />
                    <rect x="150" y={y} width="30" height="2.6" rx="1" fill="#9db4d3" />
                  </g>
                ))}

                {/* totals block (OCR / semantic hotspot) */}
                <rect x="120" y="176" width="62" height="0.8" fill="#e2e8f2" />
                <rect x="126" y="184" width="24" height="2.6" rx="1" fill="#c8d6ea" />
                <rect x="158" y="184" width="24" height="2.6" rx="1" fill="#9db4d3" />
                <rect x="126" y="192" width="20" height="2.6" rx="1" fill="#c8d6ea" />
                <rect x="158" y="192" width="24" height="2.6" rx="1" fill="#9db4d3" />
                <rect x="120" y="203" width="62" height="14" rx="2" fill="#eef4ff" />
                <rect x="126" y="208" width="18" height="3.4" rx="1" fill="#1d4a86" />
                <rect x="150" y="207" width="26" height="4.6" rx="1" fill="#0a1f3c" />

                {/* stamp */}
                <g opacity="0.85">
                  <circle cx="46" cy="228" r="17" fill="none" stroke="#1d4a86" strokeWidth="1.2" />
                  <circle cx="46" cy="228" r="12.5" fill="none" stroke="#1d4a86" strokeWidth="0.7" />
                  <path d="M36 226h20M36 231h14" stroke="#1d4a86" strokeWidth="1.1" />
                </g>

                {/* signature */}
                <path
                  d="M96 232c6-8 10 2 14-4s6-8 10-2 4 8 9 3 8-9 12-3"
                  fill="none"
                  stroke="#0a1f3c"
                  strokeWidth="1.3"
                  strokeLinecap="round"
                />
                <rect x="96" y="240" width="46" height="2" rx="1" fill="#c8d6ea" />

                {/* QR */}
                <g fill="#0a1f3c">
                  {Array.from({ length: 49 }).map((_, i) => {
                    const col = i % 7;
                    const row = Math.floor(i / 7);
                    const on = (i * 7 + row * 3) % 5 < 2 || (col < 2 && row < 2) || (col > 4 && row < 2) || (col < 2 && row > 4);
                    return on ? <rect key={i} x={150 + col * 3} y={252 + row * 3} width="2.6" height="2.6" /> : null;
                  })}
                </g>
                <rect x="16" y="252" width="120" height="2" rx="1" fill="#e4ebf5" />
                <rect x="16" y="258" width="96" height="2" rx="1" fill="#e4ebf5" />

                {/* scan line */}
                <g style={{ animation: "var(--animate-scan)" }}>
                  <rect x="0" y="0" width="200" height="1.6" fill="#06b6d4" opacity="0.9" />
                  <rect x="0" y="1.6" width="200" height="18" fill="#06b6d4" opacity="0.07" />
                </g>
              </svg>

              {/* region overlays */}
              {HOTSPOTS.map((h, i) => {
                const isActive = i === active;
                return (
                  <button
                    key={h.id}
                    type="button"
                    onMouseEnter={() => setActive(i)}
                    className="absolute cursor-crosshair text-left"
                    style={{
                      left: `${h.box.x * 100}%`,
                      top: `${h.box.y * 100}%`,
                      width: `${h.box.w * 100}%`,
                      height: `${h.box.h * 100}%`,
                    }}
                  >
                    <span
                      className="absolute inset-0 rounded-[3px] transition-all duration-300"
                      style={{
                        border: `${isActive ? 1.6 : 1}px solid ${h.color}`,
                        background: isActive ? `${h.color}14` : `${h.color}08`,
                        boxShadow: isActive ? `0 0 0 3px ${h.color}1f` : "none",
                      }}
                    />
                    <span
                      className="absolute -top-[18px] left-0 flex items-center gap-1 rounded border border-hairline bg-white px-1.5 py-[2px] font-mono text-[8.5px] whitespace-nowrap transition-opacity"
                      style={{ color: h.color, opacity: isActive ? 1 : 0.45 }}
                    >
                      {h.layer.toUpperCase()} · {h.metric}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* detector rail */}
          <div className="bg-white p-4">
            <div className="flex items-center justify-between">
              <p className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">Detector rail</p>
              <span className="flex items-center gap-1.5 font-mono text-[10px] text-[#0b6b7d]">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#0f9b8e]" />
                live
              </span>
            </div>
            <ul className="mt-3 grid gap-[5px]">
              {RAIL.map((r) => {
                const isActive = r.id === current.layer;
                const alert = r.score >= 0.5;
                return (
                  <li key={r.id} className="group">
                    <div
                      className="flex items-center gap-2 rounded-md px-1.5 py-[5px] transition-colors duration-200"
                      style={{ background: isActive ? "#f3f6fb" : "transparent" }}
                    >
                      <span
                        className="flex h-4.5 w-6 shrink-0 items-center justify-center rounded font-mono text-[8.5px] font-semibold tracking-wide"
                        style={{
                          background: alert ? (r.score >= 0.7 ? "#0a1f3c" : "#1d4a86") : "#eef1f7",
                          color: alert ? "#ffffff" : "#6288b8",
                        }}
                      >
                        {r.code}
                      </span>
                      <span className={`w-[74px] shrink-0 truncate text-[11px] ${isActive ? "text-navy-950" : "text-graphite-500"}`}>
                        {r.name}
                      </span>
                      <span className="relative h-[3px] flex-1 overflow-hidden rounded-full bg-navy-100">
                        <span
                          className="absolute inset-y-0 left-0 rounded-full transition-all duration-700"
                          style={{ width: `${r.score * 100}%`, background: alert ? "#b42318" : "#9db4d3" }}
                        />
                      </span>
                      <span className="tabular w-6 shrink-0 text-right font-mono text-[9.5px] text-graphite-500">
                        {(r.score * 100).toFixed(0)}
                      </span>
                    </div>
                  </li>
                );
              })}
            </ul>

            <div className="mt-4 rounded-lg border border-hairline bg-surface p-3">
              <p className="font-mono text-[9.5px] tracking-[0.14em] text-graphite-500 uppercase">Active region</p>
              <p className="mt-1.5 text-[12.5px] font-medium text-navy-950">{current.label}</p>
              <p className="mt-1 text-[11.5px] leading-relaxed text-graphite-500">
                {current.layerLabel} · score {(current.score * 100).toFixed(0)} · band {current.band}
              </p>
              <div className="mt-2.5 flex items-center justify-between border-t border-hairline pt-2.5">
                <span className="font-mono text-[10px] text-graphite-500">IoU 0.62 cross-layer</span>
                <span className="font-mono text-[10px] text-[#b42318]">2 methods agree</span>
              </div>
            </div>
          </div>
        </div>

        {/* evidence ticker */}
        <div className="no-scrollbar flex items-center gap-4 overflow-x-auto border-t border-hairline px-4 py-2.5">
          {[
            ["ELA residual", "11.4 dB"],
            ["PRNU r", "0.31"],
            ["DQT quality", "≈ 96"],
            ["Keypoint inliers", "184"],
            ["Arithmetic Δ", "₹ 41,250"],
            ["Watermark", "not found"],
          ].map(([k, v]) => (
            <span key={k} className="flex shrink-0 items-center gap-1.5 font-mono text-[10px] whitespace-nowrap">
              <span className="text-graphite-500 uppercase">{k}</span>
              <span className="text-navy-900">{v}</span>
            </span>
          ))}
        </div>
      </div>

      {/* floating verdict card */}
      <div className="absolute -bottom-6 -left-4 hidden w-[228px] rounded-xl border border-hairline bg-white p-3.5 shadow-[var(--shadow-lift)] sm:block">
        <div className="flex items-center justify-between">
          <p className="font-mono text-[9.5px] tracking-[0.14em] text-graphite-500 uppercase">Fused verdict</p>
          <Chip tone="alert">likely forged</Chip>
        </div>
        <div className="mt-2.5 flex items-end gap-2">
          <span className="tabular font-mono text-3xl leading-none font-semibold text-[#b42318]">78</span>
          <span className="pb-0.5 font-mono text-[10px] text-graphite-500">/100 risk · 91% conf</span>
        </div>
        <div className="mt-3 grid gap-1.5">
          {["Pixel ⇄ copy-move IoU 0.62", "Semantic Δ ₹41,250", "Digest invalid (post-sign edit)"].map((row) => (
            <p key={row} className="flex items-start gap-1.5 text-[11px] leading-snug text-graphite-700">
              <svg viewBox="0 0 12 12" className="mt-[3px] h-2.5 w-2.5 shrink-0" fill="none" stroke="#b42318" strokeWidth="1.6">
                <path d="M2 6l3 3 5-6" />
              </svg>
              {row}
            </p>
          ))}
        </div>
      </div>
    </div>
  );
}
