"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";

/* ---------------------------------- Reveal -------------------------------- */

export function Reveal({
  children,
  delay = 0,
  className = "",
  as: Tag = "div",
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
  as?: "div" | "section" | "li" | "article";
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setShown(true);
            io.disconnect();
          }
        });
      },
      { threshold: 0.12, rootMargin: "0px 0px -60px 0px" },
    );
    io.observe(node);
    return () => io.disconnect();
  }, []);

  const Component = Tag as "div";
  return (
    <Component
      ref={ref}
      className={`reveal ${shown ? "reveal-in" : ""} ${className}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      {children}
    </Component>
  );
}

/* ---------------------------------- Type ---------------------------------- */

export function Eyebrow({ children, tone = "#1a3ff5" }: { children: ReactNode; tone?: string }) {
  return (
    <div className="inline-flex items-center gap-2.5">
      <span className="h-px w-8" style={{ background: tone }} />
      <span
        className="font-mono text-[11px] font-medium tracking-[0.18em] uppercase"
        style={{ color: tone }}
      >
        {children}
      </span>
    </div>
  );
}

export function SectionHeading({
  eyebrow,
  title,
  lead,
  tone,
  align = "left",
  id,
}: {
  eyebrow: string;
  title: ReactNode;
  lead?: ReactNode;
  tone?: string;
  align?: "left" | "center";
  id?: string;
}) {
  return (
    <div className={`max-w-3xl ${align === "center" ? "mx-auto text-center" : ""}`} id={id}>
      <div className={align === "center" ? "flex justify-center" : ""}>
        <Eyebrow tone={tone}>{eyebrow}</Eyebrow>
      </div>
      <h2 className="mt-4 text-3xl leading-[1.12] font-semibold tracking-[-0.022em] text-navy-950 text-balance sm:text-4xl">
        {title}
      </h2>
      {lead ? <p className="mt-5 text-[15.5px] leading-relaxed text-graphite-500">{lead}</p> : null}
    </div>
  );
}

export function Chip({
  children,
  tone = "neutral",
  className = "",
}: {
  children: ReactNode;
  tone?: "neutral" | "navy" | "cyan" | "alert" | "live" | "outline";
  className?: string;
}) {
  const tones: Record<string, string> = {
    neutral: "bg-navy-50 text-graphite-700 border-navy-100",
    navy: "bg-navy-950 text-white border-navy-950",
    cyan: "bg-cyan-soft text-[#0b6b7d] border-[#b9e9f2]",
    alert: "bg-[#fef4f3] text-[#a32117] border-[#f0cfc9]",
    live: "bg-white text-[#0b6b7d] border-[#b9e9f2]",
    outline: "bg-white text-graphite-700 border-hairline",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-[3px] font-mono text-[10.5px] tracking-[0.08em] uppercase ${tones[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

export function LiveDot({ color = "#0f9b8e" }: { color?: string }) {
  return (
    <span className="relative flex h-1.5 w-1.5">
      <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ background: color }} />
      <span className="relative inline-flex h-1.5 w-1.5 rounded-full" style={{ background: color }} />
    </span>
  );
}

/* -------------------------------- RiskGauge ------------------------------- */

export function RiskGauge({
  value,
  confidence,
  size = 200,
  label = "Risk score",
  compact = false,
}: {
  value: number;
  confidence?: number;
  size?: number;
  label?: string;
  compact?: boolean;
}) {
  const stroke = compact ? 8 : 12;
  const r = (size - stroke * 2) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, value)) / 100;
  const arc = c * 0.75;
  const color = value >= 68 ? "#b42318" : value >= 45 ? "#b54708" : value >= 24 ? "#1d4a86" : "#0f6b4f";
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size * 0.86 }}>
      <svg width={size} height={size * 0.86} viewBox={`0 0 ${size} ${size * 0.86}`} className="overflow-visible">
        <g transform={`translate(${size / 2}, ${size / 2}) rotate(135)`}>
          <circle r={r} fill="none" stroke="#e9eef6" strokeWidth={stroke} strokeDasharray={`${arc} ${c}`} strokeLinecap="round" />
          <circle
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeDasharray={`${arc * pct} ${c}`}
            strokeLinecap="round"
            style={{ transition: "stroke-dasharray 900ms cubic-bezier(0.22,1,0.36,1), stroke 400ms ease" }}
          />
        </g>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center pt-2">
        <div className="tabular font-mono text-4xl font-semibold tracking-[-0.03em]" style={{ color }}>
          {Math.round(value)}
        </div>
        <div className="mt-0.5 font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">{label}</div>
        {confidence !== undefined ? (
          <div className="mt-2 font-mono text-[11px] text-graphite-500">
            conf <span className="tabular text-navy-800">{Math.round(confidence * 100)}%</span>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/* --------------------------------- Meters -------------------------------- */

export function Meter({
  value,
  color = "#1a3ff5",
  track = "#eaeff7",
  height = 6,
  animate = true,
}: {
  value: number;
  color?: string;
  track?: string;
  height?: number;
  animate?: boolean;
}) {
  const [w, setW] = useState(animate ? 0 : value * 100);
  useEffect(() => {
    const t = setTimeout(() => setW(Math.max(0, Math.min(1, value)) * 100), 60);
    return () => clearTimeout(t);
  }, [value]);
  return (
    <div className="w-full overflow-hidden rounded-full" style={{ height, background: track }}>
      <div
        className="h-full rounded-full"
        style={{ width: `${w}%`, background: color, transition: "width 900ms cubic-bezier(0.22,1,0.36,1)" }}
      />
    </div>
  );
}

export function StatTile({
  label,
  value,
  sub,
  accent = "#071122",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-hairline bg-white p-4 shadow-[var(--shadow-card)]">
      <div className="font-mono text-[10px] tracking-[0.16em] text-graphite-500 uppercase">{label}</div>
      <div className="mt-2 text-xl font-semibold tracking-[-0.02em]" style={{ color: accent }}>
        {value}
      </div>
      {sub ? <div className="mt-1 text-xs text-graphite-500">{sub}</div> : null}
    </div>
  );
}

export function KeyValue({ items, dense = false }: { items: { label: string; value: ReactNode }[]; dense?: boolean }) {
  return (
    <dl className="divide-y divide-hairline">
      {items.map((item) => (
        <div key={item.label} className={`flex items-baseline justify-between gap-6 ${dense ? "py-2" : "py-2.5"}`}>
          <dt className="font-mono text-[11px] tracking-[0.06em] text-graphite-500 uppercase">{item.label}</dt>
          <dd className="text-right font-mono text-[12.5px] break-all text-navy-900">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}
