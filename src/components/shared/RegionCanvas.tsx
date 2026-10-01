"use client";

import { LAYER_ACCENT, SEVERITY_STYLE } from "@/lib/format";
import type { Region } from "@/lib/forensics/types";

export interface RegionLike {
  id: string;
  label: string;
  layer: string;
  score: number;
  confidence: number;
  x: number;
  y: number;
  width: number;
  height: number;
  notes?: string;
  technique?: string;
}

/**
 * Region overlay renderer used by both the landing-page demo and the live
 * analysis dashboard. Coordinates are normalised (0..1) exactly as stored in
 * PostgreSQL, so the same component draws an uploaded JPEG or a PDF page.
 */
export function RegionCanvas({
  regions,
  imageUrl,
  aspect = 1.414,
  activeLayers,
  showHeat = true,
  selectedId,
  onSelect,
  showLabels = true,
  className = "",
  renderSurface,
}: {
  regions: RegionLike[];
  imageUrl?: string | null;
  aspect?: number;
  activeLayers?: string[] | null;
  showHeat?: boolean;
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
  showLabels?: boolean;
  className?: string;
  renderSurface?: () => React.ReactNode;
}) {
  const visible = regions.filter((r) => !activeLayers || activeLayers.length === 0 || activeLayers.includes(r.layer));

  return (
    <div
      className={`relative overflow-hidden rounded-xl border border-hairline bg-white ${className}`}
      style={{ aspectRatio: `${aspect}` }}
      onClick={() => onSelect?.(null)}
    >
      {renderSurface ? (
        renderSurface()
      ) : imageUrl ? (
        // eslint-disable-next-line @next/next/no-img-element
        <img src={imageUrl} alt="Evidence under analysis" className="absolute inset-0 h-full w-full object-cover" />
      ) : null}

      <svg className="pointer-events-none absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        <defs>
          <pattern id="heat-dots" width="1.6" height="1.6" patternUnits="userSpaceOnUse">
            <circle cx="0.8" cy="0.8" r="0.55" fill="currentColor" />
          </pattern>
        </defs>
        {showHeat
          ? visible.map((r) => {
              const accent = LAYER_ACCENT[r.layer] ?? "#1a3ff5";
              return (
                <g key={`heat-${r.id}`} style={{ color: accent, opacity: 0.1 + Math.min(0.45, r.score * 0.5) }}>
                  <rect
                    x={r.x * 100}
                    y={r.y * 100}
                    width={r.width * 100}
                    height={r.height * 100}
                    fill="url(#heat-dots)"
                    style={{ transition: "opacity 500ms ease" }}
                  />
                </g>
              );
            })
          : null}
      </svg>

      {visible.map((r) => {
        const selected = selectedId === r.id;
        const accent = LAYER_ACCENT[r.layer] ?? "#1a3ff5";
        const band = r.score >= 0.8 ? SEVERITY_STYLE.critical : r.score >= 0.6 ? SEVERITY_STYLE.high : r.score >= 0.4 ? SEVERITY_STYLE.medium : SEVERITY_STYLE.low;
        return (
          <button
            key={r.id}
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              onSelect?.(selected ? null : r.id);
            }}
            className="group absolute cursor-crosshair text-left"
            style={{
              left: `${r.x * 100}%`,
              top: `${r.y * 100}%`,
              width: `${r.width * 100}%`,
              height: `${r.height * 100}%`,
            }}
          >
            <span
              className="absolute inset-0 rounded-[3px] transition-all duration-300"
              style={{
                border: `${selected ? 2 : 1.25}px solid ${selected ? band.color : accent}`,
                background: selected ? `${band.color}0f` : "transparent",
                boxShadow: selected ? `0 0 0 3px ${band.color}1a` : "none",
              }}
            />
            {[
              "left-[-1px] top-[-1px] border-l-2 border-t-2",
              "right-[-1px] top-[-1px] border-r-2 border-t-2",
              "left-[-1px] bottom-[-1px] border-l-2 border-b-2",
              "right-[-1px] bottom-[-1px] border-r-2 border-b-2",
            ].map((pos) => (
              <span
                key={pos}
                className={`absolute h-2.5 w-2.5 transition-transform duration-300 ${pos} group-hover:scale-125`}
                style={{ borderColor: selected ? band.color : accent }}
              />
            ))}
            {showLabels ? (
              <span
                className="absolute -top-6 left-0 flex max-w-[240px] items-center gap-1.5 rounded-md border bg-white/97 px-1.5 py-[3px] font-mono text-[9.5px] whitespace-nowrap shadow-[var(--shadow-card)] transition-opacity duration-200"
                style={{ borderColor: selected ? band.border : "#e2e8f2", color: selected ? band.color : "#2b3546", opacity: selected ? 1 : 0.92 }}
              >
                <span className="h-1.5 w-1.5 rounded-full" style={{ background: accent }} />
                <span className="truncate">{r.label}</span>
                <span className="tabular ml-0.5" style={{ color: band.color }}>
                  {(r.score * 100).toFixed(0)}
                </span>
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

export function RegionLegend({
  regions,
  selectedId,
  onSelect,
}: {
  regions: RegionLike[];
  selectedId?: string | null;
  onSelect?: (id: string | null) => void;
}) {
  if (!regions.length) {
    return (
      <p className="rounded-lg border border-dashed border-hairline px-4 py-6 text-center text-[13px] text-graphite-500">
        No suspicious region survived the localisation stage.
      </p>
    );
  }
  return (
    <ul className="grid gap-2">
      {regions.map((r) => {
        const selected = selectedId === r.id;
        const accent = LAYER_ACCENT[r.layer] ?? "#1a3ff5";
        const band = r.score >= 0.8 ? SEVERITY_STYLE.critical : r.score >= 0.6 ? SEVERITY_STYLE.high : r.score >= 0.4 ? SEVERITY_STYLE.medium : SEVERITY_STYLE.low;
        return (
          <li key={r.id}>
            <button
              type="button"
              onClick={() => onSelect?.(selected ? null : r.id)}
              className={`w-full rounded-lg border px-3.5 py-3 text-left transition-all ${
                selected ? "shadow-[var(--shadow-card)]" : "hover:bg-navy-50/60"
              }`}
              style={{ borderColor: selected ? band.border : "#e2e8f2", background: selected ? band.bg : "#fff" }}
            >
              <div className="flex items-center justify-between gap-3">
                <span className="flex min-w-0 items-center gap-2">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: accent }} />
                  <span className="truncate text-[13px] font-medium text-navy-950">{r.label}</span>
                </span>
                <span className="tabular shrink-0 font-mono text-[11px]" style={{ color: band.color }}>
                  {(r.score * 100).toFixed(0)} · {r.layer}
                </span>
              </div>
              <p className="mt-1.5 text-[12px] leading-relaxed text-graphite-500">{r.notes}</p>
              <div className="mt-2 flex flex-wrap gap-1.5 font-mono text-[9.5px] tracking-[0.08em] text-graphite-500 uppercase">
                <span className="rounded border border-hairline px-1.5 py-0.5">{r.technique}</span>
                <span className="rounded border border-hairline px-1.5 py-0.5">
                  x{r.x.toFixed(2)} y{r.y.toFixed(2)} w{r.width.toFixed(2)} h{r.height.toFixed(2)}
                </span>
                <span className="rounded border border-hairline px-1.5 py-0.5">conf {(r.confidence * 100).toFixed(0)}%</span>
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
