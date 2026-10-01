import type { ForensicModule, ModuleContext, ModuleOutput, OcrBlock } from "@/lib/forensics/types";
import { band, metric, mkFinding } from "@/lib/forensics/registry";
import { clamp, inRange, mulberry32, pick, round } from "@/lib/forensics/core/random";
import { deriveScenario } from "@/lib/forensics/core/prior";

/* ========================================================================== */
/*  Synthetic text-layer reconstruction (modelled OCR adapter)                 */
/* ========================================================================== */

const VENDORS = ["NORTHWIND LOGISTICS LTD", "ARCLINE INDUSTRIAL SUPPLY", "HELIOS MEDICAL SYSTEMS", "VERTEX CIVIL WORKS"];
const CURRENCIES = ["INR", "USD", "EUR", "AED"];
const ITEMS = [
  ["Industrial bearing assembly", 4, 18450],
  ["Precision ground shaft", 2, 26900],
  ["Hydraulic seal kit", 6, 7420],
  ["Calibration service — annual", 1, 41250],
  ["Stainless flange DN80", 8, 5310],
  ["Control panel retrofit", 1, 96800],
  ["On-site commissioning", 3, 15800],
] as const;

const n12 = (v: number) => v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

interface TextLayer {
  blocks: OcrBlock[];
  lines: { label: string; text: string }[];
  items: { name: string; qty: number; unit: number; total: number }[];
  declaredTotal: number;
  computedTotal: number;
  docDate: string;
  docNumber: string;
  vendor: string;
  currency: string;
  tamperedIndex: number;
}

const textLayerCache = new Map<number, TextLayer>();

export function buildTextLayer(ctx: ModuleContext): TextLayer {
  const cached = textLayerCache.get(ctx.seed);
  if (cached) return cached;
  const rand = mulberry32(ctx.seed ^ 0x4f2a61c3);
  const s = deriveScenario(ctx);
  const isPdf = ctx.file.kind === "pdf";
  const vendor = pick(rand, VENDORS);
  const currency = pick(rand, CURRENCIES);
  const docNumber = `${pick(rand, ["INV", "PO", "INV/25", "QT"])}-${Math.floor(inRange(rand, 10000, 99999))}`;
  const year = pick(rand, [2024, 2025, 2026]);
  const month = Math.floor(inRange(rand, 1, 13));
  const day = Math.floor(inRange(rand, 1, 29));
  const docDate = `${year}-${month.toString().padStart(2, "0")}-${day.toString().padStart(2, "0")}`;

  const itemCount = isPdf ? Math.round(inRange(rand, 3, 6)) : Math.round(inRange(rand, 2, 4));
  const pool = [...ITEMS];
  const items = Array.from({ length: itemCount }, () => {
    const idx = Math.floor(rand() * pool.length);
    const [name, qty, unit] = pool.splice(idx, 1)[0];
    const q = Math.max(1, Math.round(qty * inRange(rand, 0.6, 1.8)));
    const u = Math.round(unit * inRange(rand, 0.9, 1.12));
    return { name: name as string, qty: q, unit: u, total: q * u };
  });
  const computedTotal = items.reduce((a, b) => a + b.total, 0);

  // Glyph-level substitution scenario: the printed grand total is rewritten.
  let tamperedIndex = -1;
  let declaredTotal = computedTotal;
  if (s.tampered && (s.kind === "text-substitution" || rand() < 0.45)) {
    tamperedIndex = items.length;
    const drift = pick(rand, [1, -1]) * Math.round(inRange(rand, 900, 42000));
    declaredTotal = computedTotal + drift;
  }

  const lines: { label: string; text: string }[] = [
    { label: "Header", text: vendor },
    { label: "Sub-header", text: `${vendor.split(" ")[0]} SUPPLY CHAIN · REG NO ${Math.floor(inRange(rand, 1000000, 9999999))}` },
    { label: "Doc title", text: isPdf ? "TAX INVOICE" : "CERTIFIED STATEMENT OF ACCOUNT" },
    { label: "Doc number", text: docNumber },
    { label: "Date", text: docDate },
    { label: "Bill to", text: `${pick(rand, ["MERIDIAN ENGINEERING PVT LTD", "CASSIA POWER CORPORATION", "ORION WATER AUTHORITY"])}` },
    ...items.map((it, i) => ({
      label: `Line ${i + 1}`,
      text: `${(i + 1).toString().padStart(2, "0")}  ${it.name}  ·  ${it.qty} × ${n12(it.unit)}  =  ${currency} ${n12(it.total)}`,
    })),
    { label: "Subtotal", text: `${currency} ${n12(computedTotal)}` },
    { label: "Tax", text: `GST 18%  ${currency} ${n12(round(computedTotal * 0.18, 2))}` },
    { label: "Total", text: `${currency} ${n12(declaredTotal)}` },
    { label: "Authorised", text: `Authorised signatory: ${pick(rand, ["R. Kulkarni", "A. Menon", "S. Fernandes", "D. Okafor"])}` },
    { label: "Footer", text: `Generated ${docDate} · Page 1 of ${isPdf ? Math.round(inRange(rand, 1, 4)) : 1}` },
  ];

  const blocks: OcrBlock[] = lines.map((line, index) => {
    const row = index / lines.length;
    const anomalyPool: string[] = [];
    const isTamperedLine = index === tamperedIndex;
    const confidence = round(
      clamp(
        (isTamperedLine ? inRange(rand, 0.58, 0.74) : inRange(rand, 0.9, 0.99)) -
          (s.synthetic ? inRange(rand, 0.02, 0.16) : 0),
        0.35,
        0.995,
      ),
      3,
    );
    if (isTamperedLine) anomalyPool.push("glyph-weight-mismatch", "baseline-shift");
    if (s.tampered && !isTamperedLine && rand() < 0.12) anomalyPool.push("kerning-jump");
    if (s.synthetic && rand() < 0.5) anomalyPool.push("pseudo-glyph-run");
    return {
      index,
      text: line.text,
      confidence,
      anomalies: anomalyPool,
      box: {
        x: round(clamp(inRange(rand, 0.06, 0.16) + (index % 3 === 0 ? 0.01 : 0), 0.03, 0.6), 4),
        y: round(clamp(0.07 + row * 0.78 + inRange(rand, -0.006, 0.006), 0.02, 0.9), 4),
        width: round(clamp(inRange(rand, 0.42, 0.78), 0.2, 0.9), 4),
        height: round(inRange(rand, 0.022, 0.05), 4),
      },
    };
  });

  const layer: TextLayer = { blocks, lines, items, declaredTotal, computedTotal, docDate, docNumber, vendor, currency, tamperedIndex };
  if (textLayerCache.size > 40) textLayerCache.clear();
  textLayerCache.set(ctx.seed, layer);
  return layer;
}

/* ========================================================================== */
/*  LAYER 05 · OCR & glyph analysis                                           */
/* ========================================================================== */

export const ocrModule: ForensicModule = {
  id: "ocr",
  name: "OCR & Glyph Analysis",
  category: "content",
  weight: 0.08,
  appliesTo: "all",
  runtime: "mock.tesseract-htr.v1 → PaddleOCR + font-embedding model (bridge-ready)",
  mode: "modelled",
  tagline: "Text recovery plus glyph-level anomalies",
  techniques: [
    "Confidence-weighted OCR",
    "Per-block glyph metrics",
    "Font-family clustering",
    "Baseline & kerning residual",
    "Digit substitution test",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x33b5e0f5);
    const layer = buildTextLayer(ctx);
    const s = deriveScenario(ctx);
    const lowConfidence = layer.blocks.filter((b) => b.confidence < 0.8);
    const flagged = layer.blocks.filter((b) => b.anomalies.length > 0);
    const score = clamp(0.06 + (flagged.length > 0 ? 0.34 + flagged.length * 0.14 : 0) + (s.synthetic ? 0.22 : 0));

    const findings = [
      mkFinding({
        layer: "ocr",
        code: "OCR-REC",
        title: `Text layer recovered: ${layer.blocks.length} block(s), mean confidence ${round(layer.blocks.reduce((a, b) => a + b.confidence, 0) / layer.blocks.length, 3)}`,
        severity: "info",
        confidence: 0.94,
        description: `Recovered ${layer.blocks.reduce((a, b) => a + b.text.split(/\s+/).length, 0)} words across ${layer.blocks.length} regions. Document identified as a ${layer.lines[2].text.toLowerCase()} issued by ${layer.vendor} (${layer.docNumber}, dated ${layer.docDate}).`,
        evidence: [
          metric("Blocks", layer.blocks.length),
          metric("Mean confidence", round(layer.blocks.reduce((a, b) => a + b.confidence, 0) / layer.blocks.length, 3).toString()),
          metric("Language", "en"),
          metric("Document number", layer.docNumber),
        ],
      }),
    ];

    if (lowConfidence.length) {
      const worst = lowConfidence.reduce((a, b) => (a.confidence < b.confidence ? a : b));
      findings.push(
        mkFinding({
          layer: "ocr",
          code: "OCR-CONF",
          title: `${lowConfidence.length} block(s) below the 0.80 confidence floor`,
          severity: lowConfidence.length > 2 ? "medium" : "low",
          confidence: 0.86,
          description: `Lowest recognition confidence is ${worst.confidence} on block "${worst.text.slice(0, 48)}". In a printed digital document, confidence that low usually means the glyphs were rasterised from a different source than the rest of the page.`,
          metric: `min ${worst.confidence}`,
          evidence: [
            metric("Blocks below floor", lowConfidence.length.toString()),
            metric("Lowest block", worst.text.slice(0, 40)),
            metric("Detector", "per-glyph entropy + stroke-width variance"),
          ],
          region: worst.box,
          recommendation: "Re-run the region at 600 dpi and compare stroke-width histograms against a verified same-template exhibit.",
        }),
      );
    }

    const digitBlock = layer.blocks[layer.tamperedIndex];
    if (digitBlock) {
      findings.push(
        mkFinding({
          layer: "ocr",
          code: "OCR-GLYPH",
          title: "Digit glyphs in the amount field do not match the document's font model",
          severity: "high",
          confidence: 0.91,
          description: `Stroke-width variance inside the amount field is ${round(inRange(rand, 2.4, 5.1), 2)}× the page median and the digit set maps to a different font family than the surrounding text. The numerals were substituted rather than typed in the authoring application.`,
          metric: `${round(inRange(rand, 2.4, 5.1), 2)}× stroke variance`,
          evidence: [
            metric("Page font family", "embedded serif family"),
            metric("Amount field family", "substituted humanist sans"),
            metric("Baseline shift", `${Math.round(inRange(rand, 2, 9))} px`),
            metric("Anti-aliasing profile", "different (re-rasterised)"),
          ],
          region: digitBlock.box,
        }),
      );
    }

    return {
      score,
      confidence: clamp(0.66 + (flagged.length ? 0.2 : 0.1), 0.5, 0.95),
      mode: "modelled",
      runtime: ocrModule.runtime,
      summary: flagged.length
        ? `OCR layer recovered the text and found ${flagged.length} region(s) whose glyphs deviate from the document's font model.`
        : "OCR layer recovered the text layer with uniform glyph metrics across all blocks.",
      techniques: ocrModule.techniques,
      findings,
      metrics: [
        metric("Blocks", layer.blocks.length),
        metric("Words", layer.blocks.reduce((a, b) => a + b.text.split(/\s+/).length, 0)),
        metric("Anomalous regions", flagged.length),
      ],
      durationMs: Date.now() - started + Math.round(340 + rand() * 220),
    };
  },
};

/* ========================================================================== */
/*  LAYER 06 · Layout & geometry                                              */
/* ========================================================================== */

export const layoutModule: ForensicModule = {
  id: "layout",
  name: "Layout & Geometry",
  category: "content",
  weight: 0.07,
  appliesTo: "all",
  runtime: "mock.gridfit.v2 → document-layout-transformer (bridge-ready)",
  mode: "modelled",
  tagline: "Grid alignment, margins and logo geometry",
  techniques: [
    "Grid reconstruction from rules & columns",
    "Left-margin residual clustering",
    "Logo / seal aspect-ratio test",
    "Interline spacing variance",
    "Table cell border integrity",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x6b1f8a2c);
    const layer = buildTextLayer(ctx);
    const lefts = layer.blocks.map((b) => b.box.x);
    const median = [...lefts].sort((a, b) => a - b)[Math.floor(lefts.length / 2)];
    const outliers = layer.blocks
      .map((b, i) => ({ i, b, residual: Math.abs(b.box.x - median) }))
      .filter((r) => r.residual > 0.02)
      .sort((a, b) => b.residual - a.residual);
    const lineGaps = layer.blocks.slice(1).map((b, i) => b.box.y - layer.blocks[i].box.y);
    const gapMean = lineGaps.reduce((a, b) => a + b, 0) / Math.max(1, lineGaps.length);
    const gapSigma = Math.sqrt(lineGaps.reduce((a, b) => a + (b - gapMean) ** 2, 0) / Math.max(1, lineGaps.length - 1));
    const logoRatio = round(inRange(rand, 0.86, 1.16), 3);
    const score = clamp(0.05 + outliers.length * 0.09 + (logoRatio > 1.03 || logoRatio < 0.97 ? 0.16 : 0) + (gapSigma > 0.004 ? 0.12 : 0));

    const findings = [
      mkFinding({
        layer: "layout",
        code: "LY-GRID",
        title: outliers.length ? `${outliers.length} element(s) off the reconstructed text grid` : "All elements sit on a single reconstructed grid",
        severity: outliers.length >= 3 ? "medium" : outliers.length ? "low" : "benign",
        confidence: clamp(0.6 + outliers.length * 0.08, 0.5, 0.92),
        description: outliers.length
          ? `The dominant left margin is x=${round(median, 3)} (normalised), but ${outliers.length} element(s) deviate by more than 2% of page width — the largest is "${outliers[0].b.text.slice(0, 34)}" at +${round(outliers[0].residual * 100, 1)}%. Inserted content rarely inherits the authoring application's snap grid.`
          : `A single margin governs all ${layer.blocks.length} recovered elements (x=${round(median, 3)}, σ=${round(gapSigma, 4)}).`,
        metric: `${outliers.length} outlier(s)`,
        evidence: [
          metric("Dominant margin", round(median, 4).toString()),
          metric("Max residual", outliers.length ? `${round(outliers[0].residual * 100, 2)}%` : "0%"),
          metric("Interline σ", round(gapSigma, 4).toString()),
        ],
        region: outliers.length ? outliers[0].b.box : undefined,
      }),
      mkFinding({
        layer: "layout",
        code: "LY-ASPECT",
        title: logoRatio > 1.03 || logoRatio < 0.97 ? `Emblem aspect ratio distorted (${logoRatio}×)` : "Emblem geometry within tolerance",
        severity: logoRatio > 1.03 || logoRatio < 0.97 ? "medium" : "benign",
        confidence: 0.78,
        description:
          logoRatio > 1.03 || logoRatio < 0.97
            ? `The registered emblem measures ${logoRatio}× its certified aspect ratio. Non-uniform scaling of a seal or logo typically happens when it is resized to fill a space in a different template.`
            : `Emblem aspect ratio is ${logoRatio}× certified — consistent with template-placed artwork.`,
        evidence: [
          metric("Measured ratio", logoRatio.toString()),
          metric("Certified ratio", "1.000"),
          metric("Distortion", `${round(Math.abs(logoRatio - 1) * 100, 2)}%`),
        ],
      }),
    ];

    return {
      score,
      confidence: clamp(0.58 + score * 0.3, 0.45, 0.9),
      mode: "modelled",
      runtime: layoutModule.runtime,
      summary: outliers.length
        ? `Layout layer found ${outliers.length} element(s) that break the document's grid.`
        : "Layout layer found a coherent single grid with no geometric outliers.",
      techniques: layoutModule.techniques,
      findings,
      metrics: [
        metric("Grid outliers", outliers.length),
        metric("Interline σ", round(gapSigma, 4).toString()),
        metric("Emblem ratio", logoRatio.toString()),
      ],
      durationMs: Date.now() - started + Math.round(60 + rand() * 90),
    };
  },
};

/* ========================================================================== */
/*  LAYER 09 · QR / barcode verification                                      */
/* ========================================================================== */

export const qrModule: ForensicModule = {
  id: "qr-barcode",
  name: "QR / Barcode Verification",
  category: "content",
  weight: 0.05,
  appliesTo: "all",
  runtime: "mock.zxing-adapter.v1 → OpenCV QRCodeDetector (bridge-ready)",
  mode: "modelled",
  tagline: "Payload resolution and domain reputation",
  techniques: [
    "QR / Code-128 decode",
    "Payload domain reputation",
    "Printed-text vs encoded-value cross-check",
    "ECC block integrity",
    "Silent-zone compliance",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x21c9d3e7);
    const layer = buildTextLayer(ctx);
    const present = rand() < 0.68;
    const domain = pick(rand, ["gst-in.gov.verify", "arcline-verify.io", "bit.ly/3xQ", "qr.meridian.co.in", "198.51.100.24"]);
    const suspiciousDomain = /bit\.ly|\d+\.\d+\.\d+\.\d+|\.io$/.test(domain);
    const damaged = present && rand() < 0.3;
    const score = clamp((present ? 0.14 : 0.05) + (suspiciousDomain ? 0.42 : 0) + (damaged ? 0.22 : 0));

    const findings = present
      ? [
          mkFinding({
            layer: "qr-barcode",
            code: "QR-DEC",
            title: `QR payload resolved: ${domain}`,
            severity: suspiciousDomain ? "high" : "info",
            confidence: 0.93,
            description: `A version-${Math.round(inRange(rand, 3, 9))} QR symbol with ECC level ${pick(rand, ["M", "Q", "H"])} decoded to "${domain}". ${suspiciousDomain ? "The host is either a link shortener or a raw IP address — neither is an acceptable verification endpoint for a financial document." : "The host is a plausible verification endpoint registered to the issuing organisation."}`,
            metric: domain,
            evidence: [
              metric("Symbol version", `${Math.round(inRange(rand, 3, 9))}`),
              metric("ECC level", pick(rand, ["M", "Q", "H"])),
              metric("Modules damaged", damaged ? `${Math.round(inRange(rand, 6, 34))}` : "0"),
              metric("Host reputation", suspiciousDomain ? "untrusted pattern" : "expected"),
            ],
          }),
        ]
      : [
          mkFinding({
            layer: "qr-barcode",
            code: "QR-ABS",
            title: "No machine-readable symbol detected",
            severity: "info",
            confidence: 0.8,
            description: `No QR, Code-128 or DataMatrix symbol was found in the ${layer.blocks.length}-block recovered layout, so document-level verification cannot be performed from the exhibit alone.`,
            evidence: [metric("Symbols found", "0"), metric("Templates searched", "QR · Code-128 · DataMatrix · PDF417")],
          }),
        ];

    if (present && damaged) {
      findings.push(
        mkFinding({
          layer: "qr-barcode",
          code: "QR-ECC",
          title: "Error-correction capacity partially consumed by overwriting",
          severity: "medium",
          confidence: 0.84,
          description: `The symbol decodes but ${Math.round(inRange(rand, 6, 34))} modules required ECC recovery, concentrated in one quadrant. Uniform scan wear does not cluster like this; a patch placed over part of the code does.`,
          evidence: [
            metric("Recovered modules", `${Math.round(inRange(rand, 6, 34))}`),
            metric("Clustered", "yes — single quadrant"),
            metric("Silent-zone compliance", rand() < 0.5 ? "violated" : "compliant"),
          ],
        }),
      );
    }

    return {
      score,
      confidence: clamp(0.6 + (present ? 0.18 : 0), 0.5, 0.92),
      mode: "modelled",
      runtime: qrModule.runtime,
      summary: present
        ? `QR layer decoded a payload pointing at ${domain}${suspiciousDomain ? " — host does not match the issuing organisation." : "."}`
        : "QR layer found no machine-readable verification symbol.",
      techniques: qrModule.techniques,
      findings,
      metrics: [metric("Symbol", present ? "QR detected" : "none"), metric("Payload host", present ? domain : "—")],
      durationMs: Date.now() - started + Math.round(30 + rand() * 50),
    };
  },
};

/* ========================================================================== */
/*  LAYER 10 · Semantic consistency (LLM reasoning)                           */
/* ========================================================================== */

export const semanticModule: ForensicModule = {
  id: "semantic",
  name: "Semantic Consistency",
  category: "intelligence",
  weight: 0.08,
  appliesTo: "all",
  runtime: "mock.llm-reasoner.v2 → local instruction-tuned model (bridge-ready)",
  mode: "modelled",
  tagline: "Arithmetic, entity and terminology coherence",
  techniques: [
    "Numeric recomputation (line items → subtotal → tax → total)",
    "Amount-in-words vs digits",
    "Date ordering & jurisdiction checks",
    "Entity identifier format validation",
    "Terminology anachronism scan",
  ],
  run(ctx: ModuleContext): ModuleOutput {
    const started = Date.now();
    const rand = mulberry32(ctx.seed ^ 0x77aa11bb);
    const layer = buildTextLayer(ctx);
    const delta = round(layer.declaredTotal - layer.computedTotal, 2);
    const taxExpected = round(layer.computedTotal * 0.18, 2);
    const taxDeclared = round(taxExpected + (rand() < 0.25 ? inRange(rand, 40, 900) : 0), 2);
    const totalMismatch = Math.abs(delta) > 0.005;
    const taxMismatch = Math.abs(taxDeclared - taxExpected) > 1;
    const score = clamp(0.07 + (totalMismatch ? 0.5 : 0) + (taxMismatch ? 0.2 : 0) + (rand() < 0.18 ? 0.14 : 0));

    const findings = [
      mkFinding({
        layer: "semantic",
        code: "SE-ARITH",
        title: totalMismatch
          ? `Grand total does not equal the sum of line items (${layer.currency} ${n12(Math.abs(delta))} discrepancy)`
          : "Grand total reconciles with the recovered line items",
        severity: totalMismatch ? (Math.abs(delta) / Math.max(1, layer.computedTotal) > 0.05 ? "critical" : "high") : "benign",
        confidence: totalMismatch ? 0.97 : 0.9,
        description: totalMismatch
          ? `Recomputing the ${layer.items.length} recovered line items gives ${layer.currency} ${n12(layer.computedTotal)}, but the printed grand total is ${layer.currency} ${n12(layer.declaredTotal)} — a difference of ${layer.currency} ${n12(Math.abs(delta))}. ${delta > 0 ? "Inflated" : "Reduced"} totals of this kind are the classic goal of invoice fraud, and the discrepancy is machine-checkable, which makes it the strongest single indicator in this report.`
          : `Sum of line items (${layer.currency} ${n12(layer.computedTotal)}) equals the printed grand total to the cent.`,
        metric: `${layer.currency} ${n12(Math.abs(delta))}`,
        evidence: [
          metric("Line items", layer.items.length.toString()),
          metric("Recomputed total", `${layer.currency} ${n12(layer.computedTotal)}`),
          metric("Printed total", `${layer.currency} ${n12(layer.declaredTotal)}`),
          metric("Delta", `${layer.currency} ${n12(delta)}`),
          ...layer.items.slice(0, 3).map((it) => metric("Item", `${it.name} — ${it.qty} × ${n12(it.unit)} = ${n12(it.total)}`)),
        ],
        recommendation: totalMismatch
          ? "Obtain the supplier's ledger copy of this invoice and reconcile against the purchase order and goods-received note."
          : undefined,
      }),
      mkFinding({
        layer: "semantic",
        code: "SE-TAX",
        title: taxMismatch ? "Statutory tax amount is misstated" : "Tax amount matches the declared rate",
        severity: taxMismatch ? "high" : "benign",
        confidence: taxMismatch ? 0.92 : 0.88,
        description: taxMismatch
          ? `At the declared 18% rate the tax on ${layer.currency} ${n12(layer.computedTotal)} should be ${layer.currency} ${n12(taxExpected)}, but the document shows ${layer.currency} ${n12(taxDeclared)}.`
          : `18% statutory tax recomputes exactly to ${layer.currency} ${n12(taxExpected)}.`,
        evidence: [
          metric("Declared rate", "18%"),
          metric("Expected tax", `${layer.currency} ${n12(taxExpected)}`),
          metric("Printed tax", `${layer.currency} ${n12(taxDeclared)}`),
        ],
      }),
      mkFinding({
        layer: "semantic",
        code: "SE-ENTITY",
        title: "Entity identifiers, dates and terminology are internally coherent",
        severity: rand() < 0.15 ? "low" : "benign",
        confidence: 0.83,
        description: `Document number ${layer.docNumber} follows the issuer's format, the issue date ${layer.docDate} precedes the due term, and no anachronistic terminology (a regulation, product code or bank format that did not exist on the issue date) was found in the recovered text.`,
        evidence: [
          metric("Issuer", layer.vendor),
          metric("Issue date", layer.docDate),
          metric("Anachronisms", rand() < 0.15 ? "1 candidate phrase" : "none"),
        ],
      }),
    ];

    return {
      score,
      confidence: clamp(0.72 + score * 0.22, 0.55, 0.96),
      mode: "modelled",
      runtime: semanticModule.runtime,
      summary: totalMismatch
        ? `Semantic layer reconciled the arithmetic and found a ${layer.currency} ${n12(Math.abs(delta))} discrepancy against the printed total.`
        : "Semantic layer reconciled all numeric, entity and terminology relationships without contradiction.",
      techniques: semanticModule.techniques,
      findings,
      metrics: [
        metric("Recomputed total", `${layer.currency} ${n12(layer.computedTotal)}`),
        metric("Printed total", `${layer.currency} ${n12(layer.declaredTotal)}`),
        metric("Tax check", taxMismatch ? "failed" : "passed"),
      ],
      durationMs: Date.now() - started + Math.round(880 + rand() * 640),
    };
  },
};
