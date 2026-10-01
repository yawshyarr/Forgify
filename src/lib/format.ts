export interface SeverityStyle {
  dot: string;
  text: string;
  bg: string;
  border: string;
  color: string;
  label: string;
}

export const SEVERITY_STYLE: Record<string, SeverityStyle> = {
  critical: { dot: "#8f1d1d", text: "#8f1d1d", bg: "#fdf2f2", border: "#f0c9c9", color: "#8f1d1d", label: "Critical" },
  high: { dot: "#b42318", text: "#a32117", bg: "#fef4f3", border: "#f2cfc9", color: "#a32117", label: "High" },
  medium: { dot: "#b54708", text: "#9a4109", bg: "#fffaeb", border: "#f0dcae", color: "#9a4109", label: "Medium" },
  low: { dot: "#1d4a86", text: "#17427a", bg: "#f3f7fd", border: "#cfdeee", color: "#17427a", label: "Low" },
  info: { dot: "#3a66a0", text: "#2f5a99", bg: "#f5f8fc", border: "#d8e4f1", color: "#2f5a99", label: "Info" },
  benign: { dot: "#4b5a6e", text: "#43536a", bg: "#f6f8fa", border: "#dde3ea", color: "#43536a", label: "Benign" },
};

export const LAYER_ACCENT: Record<string, string> = {
  pixel: "#1a3ff5",
  compression: "#2f5cff",
  metadata: "#06b6d4",
  provenance: "#0ea5a5",
  ocr: "#133a6f",
  layout: "#3a66a0",
  "copy-move": "#1630d8",
  signature: "#55637a",
  "qr-barcode": "#1d4a86",
  semantic: "#5c85ff",
  aigc: "#071122",
};

export function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function fmtDate(value: string | Date): string {
  const d = typeof value === "string" ? new Date(value) : value;
  return d.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function riskBand(risk: number): { label: string; color: string; bg: string; border: string } {
  if (risk >= 86) return { label: "Forged", color: "#8f1d1d", bg: "#fdf2f2", border: "#eec9c9" };
  if (risk >= 68) return { label: "Likely forged", color: "#b42318", bg: "#fef4f3", border: "#f2cfc9" };
  if (risk >= 45) return { label: "Suspicious", color: "#b54708", bg: "#fffaeb", border: "#f0dcae" };
  if (risk >= 24) return { label: "Low risk", color: "#17427a", bg: "#f3f7fd", border: "#cfdeee" };
  return { label: "Authentic", color: "#0f6b4f", bg: "#f1faf6", border: "#c6e6d9" };
}

export function verdictTone(verdict: string): string {
  if (verdict.includes("forged")) return "#b42318";
  if (verdict === "suspicious") return "#b54708";
  if (verdict === "low-risk") return "#17427a";
  return "#0f6b4f";
}

export function shortHash(hash: string, size = 10): string {
  return `${hash.slice(0, size)}…${hash.slice(-6)}`;
}
