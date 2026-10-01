import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Forgify | Multi-Layer AI-Assisted Digital Forensics System",
  description:
    "Research-grade forensic platform that fuses pixel, metadata, provenance, OCR, layout, compression, copy-move, signature, QR/barcode, semantic and generative-AI evidence to detect image, document, metadata and AIGC forgeries.",
  keywords: [
    "digital forensics",
    "image forgery detection",
    "document forensics",
    "copy-move forgery",
    "generative AI detection",
    "evidence fusion",
  ],
  openGraph: {
    title: "Forgify — Investigate Every Layer. Detect Every Forgery.",
    description:
      "Multi-layer AI-assisted digital forensics system for detecting image, document, metadata and generative-AI-based forgeries.",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#061529",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-white font-sans text-ink antialiased">{children}</body>
    </html>
  );
}
