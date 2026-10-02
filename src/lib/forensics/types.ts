/**
 * ============================================================================
 *  Forgify · Forensic type contracts
 * ============================================================================
 *  Every detector module — whether it is a TypeScript reference implementation,
 *  a deterministic modelled-inference adapter, or a real Python/OpenCV service
 *  reached through the HTTP bridge — MUST return these structures.
 *
 *  The JSON envelope below is exactly what `POST /api/analyze` returns and what
 *  gets persisted to PostgreSQL (`analyses.report`), so the FastAPI service in
 *  /python can be swapped in without touching a single React component.
 * ============================================================================
 */

export type LayerId =
  | "pixel"
  | "metadata"
  | "provenance"
  | "ocr"
  | "layout"
  | "compression"
  | "copy-move"
  | "signature"
  | "qr-barcode"
  | "semantic"
  | "aigc"
  | "ml-classifier"
  | "reference";

export type Severity = "benign" | "info" | "low" | "medium" | "high" | "critical";

export type FileKind = "pdf" | "jpeg" | "png" | "raster" | "unknown";

export type Verdict = "authentic" | "low-risk" | "suspicious" | "likely-forged" | "forged";

export type ExecutionMode = "live" | "modelled" | "bridge";

/** Normalised box in 0..1 space relative to the rendered page / image. */
export interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface Region extends Box {
  id: string;
  label: string;
  layer: LayerId;
  score: number;
  confidence: number;
  notes: string;
  technique: string;
}

/** One physical suspicious area after overlapping detector observations merge. */
export interface UnifiedRegion {
  id: string;
  bbox: Box;
  regionType: string;
  detectors: string[];
  scores: Record<string, number>;
  confidence: number;
  evidence: string[];
  whySuspicious: string;
}

export interface EvidencePair {
  label: string;
  value: string;
}

export interface Finding {
  id: string;
  layer: LayerId;
  code: string;
  title: string;
  severity: Severity;
  confidence: number;
  description: string;
  metric?: string;
  evidence: EvidencePair[];
  region?: Box;
  recommendation?: string;
}

export type LayerStatus = "pass" | "review" | "alert" | "skipped";

export interface LayerResult {
  layer: LayerId;
  name: string;
  category: "signal" | "container" | "content" | "manipulation" | "intelligence";
  weight: number;
  score: number;
  confidence: number;
  status: LayerStatus;
  mode: ExecutionMode;
  runtime: string;
  durationMs: number;
  summary: string;
  techniques: string[];
  findings: Finding[];
  metrics: EvidencePair[];
  heatmap?: string | null;
}

export interface PipelineStep {
  step: number;
  key: string;
  label: string;
  detail: string;
  status: "ok" | "warn" | "alert";
  durationMs: number;
}

export interface FusionContribution {
  layer: LayerId;
  name: string;
  weight: number;
  score: number;
  contribution: number;
  status: LayerStatus;
}

export interface FusionResult {
  method: string;
  riskScore: number;
  confidence: number;
  agreement: number;
  entropy: number;
  alertCount: number;
  contributions: FusionContribution[];
  familyEvidence?: Array<{ family: string; score: number; weight: number; contribution: number; members: string[]; findingCount: number }>;
  rationale: string[];
}

export interface OcrBlock {
  index: number;
  text: string;
  box: Box;
  confidence: number;
  anomalies: string[];
}

export interface OcrResult {
  engine: string;
  mode: ExecutionMode;
  language: string;
  wordCount: number;
  meanConfidence: number;
  text: string;
  blocks: OcrBlock[];
}

export interface MLClassification {
  label: "GENUINE" | "FORGED";
  confidence: number;
  forgeryType: string | null;
  forgeryTypeConfidence: number | null;
}

export interface MetadataEntry {
  group: string;
  key: string;
  value: string;
  source: string;
  flag?: "tamper" | "missing" | "ok" | "info";
}

export interface ContainerFacts {
  kind: FileKind;
  declaredType: string;
  detectedType: string;
  typeMismatch: boolean;
  width?: number;
  height?: number;
  pageCount?: number;
  exifPresent: boolean;
  xmpPresent: boolean;
  iccPresent: boolean;
  thumbnailPresent: boolean;
  quantizationQuality?: number;
  restartMarkers: boolean;
  incrementalUpdates: number;
  producer?: string;
  creatorTool?: string;
  signed: boolean;
  encrypted: boolean;
  javascript: boolean;
  imageObjects: number;
  filters: string[];
  containerNotes: string[];
}

export interface ReferenceFacts {
  mode: "reference-free" | "reference-based";
  candidateId?: string;
  candidateLabel?: string;
  similarity?: number;
  deltaNotes: string[];
  comparedLayers: LayerId[];
}

export interface ReferenceComparisonEvidence {
  aligned: boolean;
  alignmentConfidence: number;
  changedRegions: Array<{ bbox: Box; changeType: string; score: number; confidence: number; supportingEvidence: string[] }>;
  unchangedRegions: Array<{ bbox: Box; score: number; supportingEvidence: string[] }>;
  textChanges: Array<{ bbox: Box; changeType: string; score: number; confidence: number; supportingEvidence: string[] }>;
  imageChanges: Array<{ bbox?: Box; changeType: string; score: number; confidence: number; supportingEvidence: string[] }>;
  structuralDifference: number;
  heatmap?: string | null;
}

export interface HashBundle {
  md5: string;
  sha1: string;
  sha256: string;
  blurHashFingerprint: string;
  byteEntropy: number;
}

export interface EngineIdentity {
  name: string;
  version: string;
  backend: "typescript-reference" | "python-fastapi";
  modulesRegistered: number;
  modulesExecuted: number;
}

export interface AnalysisReport {
  id: string;
  caseCode: string;
  createdAt: string;
  durationMs: number;
  engine: EngineIdentity;
  file: {
    name: string;
    extension: string;
    mimeType: string;
    sizeBytes: number;
    kind: FileKind;
    dimensions?: string;
    pages?: number;
  };
  hashes: HashBundle;
  container: ContainerFacts;
  metadata: MetadataEntry[];
  ocr: OcrResult;
  mlClassification: MLClassification | null;
  layers: LayerResult[];
  findings: Finding[];
  regions: Region[];
  unifiedRegions?: UnifiedRegion[];
  regionFindings?: Array<{
    id: string;
    regionId: string;
    regionType: string;
    bbox: Box;
    confidence: number;
    evidence: string[];
    description: string;
  }>;
  fusion: FusionResult;
  verdict: {
    label: Verdict;
    riskScore: number;
    confidence: number;
    recommendation: string;
    chainOfCustody: string;
  };
  pipeline: PipelineStep[];
  reference: ReferenceFacts;
  referenceComparison?: ReferenceComparisonEvidence | null;
  identityFields?: Array<{ fieldType: string; text: string; bbox: Box; confidence: number }>;
  identityFieldComparisons?: Array<Record<string, unknown>>;
  identityFindings?: Array<Record<string, unknown>>;
  limitations: string[];
}

export interface ModuleContext {
  file: AnalysisReport["file"];
  bytes: Uint8Array;
  seed: number;
  container: ContainerFacts;
  metadata: MetadataEntry[];
  reference: ReferenceFacts;
  rand: () => number;
}

export interface ModuleOutput {
  score: number;
  confidence: number;
  mode: ExecutionMode;
  runtime: string;
  summary: string;
  techniques: string[];
  findings: Finding[];
  metrics: EvidencePair[];
  regions?: Omit<Region, "id">[];
  durationMs: number;
  skipped?: boolean;
}

export interface ForensicModule {
  id: LayerId;
  name: string;
  category: LayerResult["category"];
  weight: number;
  appliesTo: FileKind[] | "all";
  runtime: string;
  mode: ExecutionMode;
  tagline: string;
  techniques: string[];
  run(ctx: ModuleContext): ModuleOutput;
}
