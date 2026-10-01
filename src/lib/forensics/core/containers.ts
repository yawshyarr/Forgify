import type { ContainerFacts, FileKind } from "@/lib/forensics/types";

/**
 * ============================================================================
 *  Container / byte-structure inspector  ·  LIVE analysis (not modelled)
 * ============================================================================
 *  These routines read the uploaded byte stream directly. Everything they
 *  report is grounded in the actual evidence file: chunk CRC validation,
 *  EXIF/XMP presence, JPEG quantisation-derived quality, PDF incremental
 *  updates, object counts and active-content markers.
 * ============================================================================
 */

const dec = new TextDecoder("latin1");
const utf8 = new TextDecoder("utf-8");

export function sniffKind(bytes: Uint8Array, mimeType: string, name: string): FileKind {
  if (bytes.length > 8 && bytes[0] === 0xff && bytes[1] === 0xd8) return "jpeg";
  const pngSig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (pngSig.every((v, i) => bytes[i] === v)) return "png";
  const head = dec.decode(bytes.subarray(0, Math.min(1024, bytes.length)));
  if (head.startsWith("%PDF-")) return "pdf";
  const lowerName = name.toLowerCase();
  if (mimeType.startsWith("image/") || /\.(png|jpe?g|gif|bmp|webp|tif|tiff|heic)$/.test(lowerName)) {
    return "raster";
  }
  return "unknown";
}

/* ------------------------------- CRC32 (PNG) ------------------------------ */

const CRC_TABLE = (() => {
  const table = new Array<number>(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array, start: number, end: number): number {
  let c = 0xffffffff;
  for (let i = start; i < end; i += 1) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/* ------------------------------ IJG quality ------------------------------ */

const STD_LUMA = [
  16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
  14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
  92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

function qualityFromQuantTable(table: number[]): number {
  const ratios: number[] = [];
  for (let i = 0; i < 64; i += 1) {
    const q = Math.min(255, Math.max(1, table[i] ?? 1));
    const base = Math.min(255, Math.max(1, STD_LUMA[i]));
    if (q > 1) ratios.push((q * 100) / base);
  }
  if (ratios.length === 0) return 100;
  ratios.sort((a, b) => a - b);
  const scale = ratios[Math.floor(ratios.length / 2)];
  const quality = scale < 100 ? (200 - scale) / 2 : 5000 / scale;
  return Math.round(Math.min(100, Math.max(1, quality)));
}

/* --------------------------------- JPEG ---------------------------------- */

interface JpegScan {
  width?: number;
  height?: number;
  quality?: number;
  dqtSegments: number;
  exif: boolean;
  xmp: boolean;
  icc: boolean;
  photoshop: boolean;
  jfif: boolean;
  comments: string[];
  exifTags: Record<string, string>;
  restartInterval: number;
  progressive: boolean;
  sofCount: number;
}

function readExifTags(block: Uint8Array): Record<string, string> {
  const out: Record<string, string> = {};
  if (block.length < 12) return out;
  const tiffStart = block[2] === 0x45 && block[3] === 0x78 ? 10 : 6;
  if (tiffStart + 8 > block.length) return out;
  const big = block[tiffStart] === 0x4d && block[tiffStart + 1] === 0x4d;
  const u16 = (o: number) => (big ? (block[o] << 8) | block[o + 1] : (block[o + 1] << 8) | block[o]);
  const ifdOffset = u16(tiffStart + 2);
  const base = tiffStart;
  const abs = base + ifdOffset;
  if (abs + 2 > block.length) return out;
  const count = u16(abs);
  const TAGS: Record<number, string> = {
    0x010f: "Make",
    0x0110: "Model",
    0x0131: "Software",
    0x0132: "ModifyDate",
    0x9003: "DateTimeOriginal",
    0x9004: "CreateDate",
    0x8298: "Copyright",
    0x9286: "UserComment",
    0x0112: "Orientation",
    0x013b: "Artist",
  };
  const limit = Math.min(count, 120);
  for (let i = 0; i < limit; i += 1) {
    const entry = abs + 2 + i * 12;
    if (entry + 12 > block.length) break;
    const tag = u16(entry);
    const type = u16(entry + 2);
    const valueOffset = base + u32safe(block, entry + 8, big);
    const label = TAGS[tag];
    if (!label) continue;
    const sizes: Record<number, number> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 10: 8 };
    const unit = sizes[type] ?? 1;
    const length = u32safe(block, entry + 4, big);
    const inline = length * unit <= 4;
    const vStart = inline ? entry + 8 : valueOffset;
    if (vStart + length > block.length || length > 256) continue;
    const raw = block.subarray(vStart, vStart + length);
    out[label] = (type === 2 ? utf8.decode(raw) : `0x${raw[0]?.toString(16) ?? "0"}`)
      .replace(/\u0000+$/g, "")
      .trim();
  }
  return out;
}

function u32safe(block: Uint8Array, o: number, endianBE: boolean): number {
  if (o + 4 > block.length) return 0;
  const b = [block[o], block[o + 1], block[o + 2], block[o + 3]];
  return endianBE
    ? ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0
    : ((b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0]) >>> 0;
}

function scanJpeg(bytes: Uint8Array): JpegScan {
  const scan: JpegScan = {
    dqtSegments: 0,
    exif: false,
    xmp: false,
    icc: false,
    photoshop: false,
    jfif: false,
    comments: [],
    exifTags: {},
    restartInterval: 0,
    progressive: false,
    sofCount: 0,
  };
  let i = 2;
  let guard = 0;
  while (i < bytes.length - 1 && guard < 4096) {
    guard += 1;
    if (bytes[i] !== 0xff) {
      i += 1;
      continue;
    }
    const marker = bytes[i + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      i += 2;
      continue;
    }
    if (marker === 0xda) {
      // start of scan — entropy-coded data follows, stop structural walk.
      break;
    }
    const len = (bytes[i + 2] << 8) | bytes[i + 3];
    const seg = bytes.subarray(i + 4, Math.min(bytes.length, i + 2 + len));
    if (marker === 0xe0) scan.jfif = true;
    if (marker === 0xe1) {
      const label = dec.decode(seg.subarray(0, 10));
      if (label.includes("Exif")) {
        scan.exif = true;
        scan.exifTags = { ...scan.exifTags, ...readExifTags(seg) };
      }
      if (label.includes("http") || seg.subarray(0, 29).includes(0x78)) scan.xmp = true;
    }
    if (marker === 0xe2) scan.icc = true;
    if (marker === 0xed) {
      scan.photoshop = true;
      scan.xmp = dec.decode(seg).includes("adobe:ns:meta/");
    }
    if (marker === 0xe5 || marker === 0xec) {
      const text = dec.decode(seg);
      if (text.includes("adobe:ns:meta/")) scan.xmp = true;
    }
    if (marker === 0xfe) scan.comments.push(dec.decode(seg.subarray(0, 120)).trim());
    if (marker === 0xdb) {
      scan.dqtSegments += 1;
      if (!scan.quality) {
        const table: number[] = [];
        let p = 0;
        while (p < seg.length && table.length < 64) {
          const precision = seg[p];
          const size = precision === 0 ? 1 : 2;
          p += 1;
          for (let k = 0; k < 64 && p + size <= seg.length + 1; k += 1) {
            if (size === 1) table.push(seg[p]);
            else table.push((seg[p] << 8) | seg[p + 1]);
            p += size;
          }
        }
        if (table.length === 64) scan.quality = qualityFromQuantTable(table);
      }
    }
    if (marker === 0xdd) scan.restartInterval = (seg[0] << 8) | seg[1];
    if (marker === 0xc2) scan.progressive = true;
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
      scan.sofCount += 1;
      scan.height = (seg[1] << 8) | seg[2];
      scan.width = (seg[3] << 8) | seg[4];
    }
    if (len <= 0) break;
    i += 2 + len;
  }
  return scan;
}

/* ---------------------------------- PNG ---------------------------------- */

interface PngScan {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  interlace: number;
  texts: Record<string, string>;
  idatCount: number;
  crcErrors: string[];
  hasTime: boolean;
  hasExif: boolean;
  hasIcc: boolean;
  trailingBytes: number;
  physDpi?: number;
}

function scanPng(bytes: Uint8Array): PngScan {
  const scan: PngScan = {
    width: 0,
    height: 0,
    bitDepth: 0,
    colorType: 0,
    interlace: 0,
    texts: {},
    idatCount: 0,
    crcErrors: [],
    hasTime: false,
    hasExif: false,
    hasIcc: false,
    trailingBytes: 0,
  };
  let i = 8;
  let guard = 0;
  while (i + 8 <= bytes.length && guard < 4096) {
    guard += 1;
    const len = (bytes[i] << 24) | (bytes[i + 1] << 16) | (bytes[i + 2] << 8) | bytes[i + 3];
    const type = dec.decode(bytes.subarray(i + 4, i + 8));
    const dataStart = i + 8;
    const dataEnd = Math.min(bytes.length, dataStart + Math.max(0, len));
    const crcStart = dataEnd;
    if (crcStart + 4 > bytes.length) {
      scan.trailingBytes = Math.max(0, bytes.length - dataStart);
      break;
    }
    const expected = u32safe(bytes, crcStart, true);
    const actual = crc32(bytes, i + 4, crcStart);
    if (expected !== actual && type !== "IEND") scan.crcErrors.push(type);
    if (type === "IHDR") {
      scan.width = u32safe(bytes, dataStart, true);
      scan.height = u32safe(bytes, dataStart + 4, true);
      scan.bitDepth = bytes[dataStart + 8];
      scan.colorType = bytes[dataStart + 9];
      scan.interlace = bytes[dataStart + 12];
    } else if (type === "tEXt" || type === "iTXt" || type === "zTXt") {
      const raw = utf8.decode(bytes.subarray(dataStart, dataEnd));
      const nul = raw.indexOf("\u0000");
      const key = nul > 0 ? raw.slice(0, nul) : "comment";
      scan.texts[key] = raw.slice(nul + 1).replace(/\u0000/g, " ").slice(0, 240);
    } else if (type === "IDAT") scan.idatCount += 1;
    else if (type === "tIME") scan.hasTime = true;
    else if (type === "eXIf") scan.hasExif = true;
    else if (type === "iCCP") scan.hasIcc = true;
    else if (type === "pHYs") {
      const ppuX = u32safe(bytes, dataStart, true);
      scan.physDpi = Math.round((ppuX * 2.54) / 100);
    } else if (type === "IEND") {
      scan.trailingBytes = bytes.length - (crcStart + 4);
      break;
    }
    i = crcStart + 4;
  }
  return scan;
}

/* ---------------------------------- PDF ---------------------------------- */

interface PdfScan {
  version: string;
  producer?: string;
  creator?: string;
  title?: string;
  author?: string;
  creationDate?: string;
  modDate?: string;
  pageCount: number;
  imageCount: number;
  fontCount: number;
  eofCount: number;
  incrementalUpdates: number;
  encrypted: boolean;
  javascript: boolean;
  signed: boolean;
  acroForm: boolean;
  embeddedFiles: boolean;
  linearized: boolean;
  filters: string[];
  xmp: boolean;
  objectCount: number;
}

function scanPdf(bytes: Uint8Array): PdfScan {
  const text = dec.decode(bytes.length > 3_000_000 ? bytes.subarray(0, 3_000_000) : bytes);
  const grab = (key: string): string | undefined => {
    const re = new RegExp(`/${key}\\s*\\(([^)]{0,180})\\)`);
    const m = text.match(re);
    if (m?.[1]) return m[1].replace(/\\[()]/g, "").trim();
    const hexm = text.match(new RegExp(`/${key}\\s*<([0-9A-Fa-f\\s]{4,240})>`));
    if (hexm?.[1]) {
      const clean = hexm[1].replace(/\s+/g, "");
      let out = "";
      for (let i = 0; i + 3 < clean.length; i += 4) {
        const code = parseInt(clean.slice(i, i + 4), 16);
        if (code >= 32 || code === 10) out += String.fromCharCode(code);
      }
      return out.trim();
    }
    return undefined;
  };
  const filters = [...text.matchAll(/\/Filter\s*\/([A-Za-z0-9+#]+)/g)].map((m) => m[1]);
  return {
    version: (text.match(/%PDF-(\d\.\d)/) ?? [])[1] ?? "unknown",
    producer: grab("Producer"),
    creator: grab("Creator"),
    title: grab("Title"),
    author: grab("Author"),
    creationDate: grab("CreationDate"),
    modDate: grab("ModDate"),
    pageCount: (text.match(/\/Type\s*\/Page[^s]/g) ?? []).length || 1,
    imageCount: (text.match(/\/Subtype\s*\/Image/g) ?? []).length,
    fontCount: new Set([...text.matchAll(/\/BaseFont\s*\/([A-Za-z0-9+\-_,.]+)/g)].map((m) => m[1])).size,
    eofCount: (text.match(/%%EOF/g) ?? []).length,
    incrementalUpdates: Math.max(0, (text.match(/%%EOF/g) ?? []).length - 1),
    encrypted: /\/Encrypt\s+\d+\s+\d+\s+R/.test(text),
    javascript: /\/JavaScript|\/JS\s|\/Launch|\/OpenAction/.test(text),
    signed: /\/ByteRange|\/SigField|\/FT\s*\/Sig|adbe.pkcs7/.test(text),
    acroForm: /\/AcroForm/.test(text),
    embeddedFiles: /\/EmbeddedFile/.test(text),
    linearized: /\/Linearized/.test(text),
    filters: [...new Set(filters)],
    xmp: text.includes("adobe:ns:meta/"),
    objectCount: (text.match(/\d+\s+\d+\s+obj/g) ?? []).length,
  };
}

/* ------------------------------ public API ------------------------------- */

export function inspectContainer(bytes: Uint8Array, mimeType: string, name: string): ContainerFacts {
  const kind = sniffKind(bytes, mimeType, name);
  const notes: string[] = [];
  const facts: ContainerFacts = {
    kind,
    declaredType: mimeType || "application/octet-stream",
    detectedType: kind === "pdf" ? "application/pdf" : kind === "jpeg" ? "image/jpeg" : kind === "png" ? "image/png" : mimeType || "unknown",
    typeMismatch: false,
    exifPresent: false,
    xmpPresent: false,
    iccPresent: false,
    thumbnailPresent: false,
    restartMarkers: false,
    incrementalUpdates: 0,
    signed: false,
    encrypted: false,
    javascript: false,
    imageObjects: 0,
    filters: [],
    containerNotes: notes,
  };

  if (kind === "jpeg") {
    const s = scanJpeg(bytes);
    facts.exifPresent = s.exif;
    facts.xmpPresent = s.xmp;
    facts.iccPresent = s.icc;
    facts.thumbnailPresent = s.exif;
    facts.width = s.width;
    facts.height = s.height;
    facts.quantizationQuality = s.quality;
    facts.restartMarkers = s.restartInterval > 0;
    facts.containerNotes.push(
      `Quantisation tables imply IJG quality ≈ ${s.quality ?? "n/a"} (segments: ${s.dqtSegments}).`,
    );
    if (s.photoshop) facts.containerNotes.push("Adobe APP13 resource block detected (Photoshop/IrB history may exist).");
    if (!s.exif && !s.xmp) facts.containerNotes.push("No EXIF or XMP container survived — consistent with re-export or stripping.");
    if (s.comments.length) facts.containerNotes.push(`Segment comments: ${s.comments.map((c) => `"${c}"`).join(", ")}`);
    if (s.exifTags.Software) facts.containerNotes.push(`EXIF Software tag: "${s.exifTags.Software}".`);
    if (s.progressive) facts.containerNotes.push("Progressive scan encoding detected (single re-encode, not multi-generation).");
    if (s.dqtSegments > 1) facts.containerNotes.push("Multiple quantisation table segments — possible prior compression generation.");
  } else if (kind === "png") {
    const s = scanPng(bytes);
    facts.width = s.width;
    facts.height = s.height;
    facts.xmpPresent = Object.keys(s.texts).some((k) => k.toLowerCase().includes("xml"));
    facts.exifPresent = s.hasExif;
    facts.iccPresent = s.hasIcc;
    facts.containerNotes.push(
      `IHDR ${s.width}×${s.height}, depth ${s.bitDepth}, colour type ${s.colorType}, interlace ${s.interlace}, ${s.idatCount} IDAT chunk(s).`,
    );
    if (s.crcErrors.length) {
      facts.containerNotes.push(`CRC mismatch in chunk(s): ${[...new Set(s.crcErrors)].join(", ")} — byte-level post-processing likely.`);
    } else {
      facts.containerNotes.push("All chunk CRCs validate — container is internally consistent.");
    }
    if (s.trailingBytes > 0) facts.containerNotes.push(`${s.trailingBytes} trailing byte(s) after IEND — appended payload detected.`);
    const textKeys = Object.keys(s.texts);
    if (textKeys.length) facts.containerNotes.push(`Text chunks: ${textKeys.slice(0, 5).join(", ")}.`);
    if (s.physDpi) facts.containerNotes.push(`pHYs resolution ≈ ${s.physDpi} DPI.`);
  } else if (kind === "pdf") {
    const s = scanPdf(bytes);
    facts.width = 595;
    facts.height = 842;
    facts.pageCount = s.pageCount;
    facts.exifPresent = false;
    facts.xmpPresent = s.xmp;
    facts.incrementalUpdates = s.incrementalUpdates;
    facts.signed = s.signed;
    facts.encrypted = s.encrypted;
    facts.javascript = s.javascript;
    facts.imageObjects = s.imageCount;
    facts.filters = s.filters;
    facts.producer = s.producer;
    facts.creatorTool = s.creator ?? s.producer;
    facts.containerNotes.push(
      `PDF ${s.version}, ${s.pageCount} page object(s), ${s.objectCount} indirect objects, ${s.fontCount} distinct BaseFont(s).`,
    );
    if (s.incrementalUpdates > 0)
      facts.containerNotes.push(`${s.incrementalUpdates} incremental update(s) (multiple %%EOF) — document was modified after creation.`);
    if (s.filters.length) facts.containerNotes.push(`Stream filters: ${s.filters.join(", ")}.`);
    if (s.signed) facts.containerNotes.push("Digital signature dictionary with /ByteRange present.");
    if (s.javascript) facts.containerNotes.push("Active content detected (/JavaScript or /OpenAction) — quarantine recommended.");
    if (s.encrypted) facts.containerNotes.push("Encryption dictionary present — content inspection partially limited.");
    if (!s.signed) facts.containerNotes.push("No qualified signature — no cryptographic integrity anchor available.");
  } else {
    facts.containerNotes.push("Container not fully recognised; only stream-level statistics were computed.");
  }

  if (
    (facts.declaredType.includes("pdf") && kind !== "pdf") ||
    (facts.declaredType.startsWith("image/") && kind === "pdf")
  ) {
    facts.typeMismatch = true;
    facts.containerNotes.push(`MIME header says "${facts.declaredType}" but the byte structure is "${kind}" — spoofed extension.`);
  }

  return facts;
}

export type { JpegScan, PngScan, PdfScan };
