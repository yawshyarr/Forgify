import {
  index,
  integer,
  jsonb,
  pgTable,
  real,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";
import type { AnalysisReport, Finding, LayerId, Region } from "@/lib/forensics/types";

/**
 * Immutable record of a single forensic examination.
 * `report` keeps the full structured JSON envelope emitted by POST /api/analyze
 * so any historical case can be re-rendered byte-for-byte.
 */
export const analyses = pgTable(
  "analyses",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    caseCode: text("case_code").notNull(),
    filename: text("filename").notNull(),
    mimeType: text("mime_type").notNull(),
    sizeBytes: integer("size_bytes").notNull(),
    sha256: text("sha256").notNull(),
    md5: text("md5").notNull(),
    sha1: text("sha1").notNull(),
    verdict: text("verdict").notNull(),
    riskScore: integer("risk_score").notNull(),
    confidence: integer("confidence").notNull(),
    recommendation: text("recommendation").notNull(),
    layerScores: jsonb("layer_scores").$type<Record<string, number>>().notNull(),
    engine: text("engine").notNull(),
    executionMode: text("execution_mode").notNull(),
    durationMs: integer("duration_ms").notNull(),
    referenceMode: text("reference_mode").notNull(),
    assetDataUrl: text("asset_data_url"),
    report: jsonb("report").$type<AnalysisReport>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("analyses_created_at_idx").on(table.createdAt),
    index("analyses_sha256_idx").on(table.sha256),
  ],
);

/** Normalised per-finding rows so evidence can be queried/audited in SQL. */
export const findings = pgTable(
  "findings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    analysisId: uuid("analysis_id")
      .notNull()
      .references(() => analyses.id, { onDelete: "cascade" }),
    layer: text("layer").$type<LayerId>().notNull(),
    code: text("code").notNull(),
    title: text("title").notNull(),
    severity: text("severity").notNull(),
    confidence: real("confidence").notNull(),
    description: text("description").notNull(),
    evidence: jsonb("evidence").$type<Finding["evidence"]>().notNull(),
    region: jsonb("region").$type<Finding["region"]>(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [index("findings_analysis_idx").on(table.analysisId)],
);

/** Localised suspicious regions (normalised coordinates, 0..1 space). */
export const regions = pgTable(
  "regions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    analysisId: uuid("analysis_id")
      .notNull()
      .references(() => analyses.id, { onDelete: "cascade" }),
    label: text("label").notNull(),
    layer: text("layer").$type<LayerId>().notNull(),
    score: real("score").notNull(),
    confidence: real("confidence").notNull(),
    x: real("x").notNull(),
    y: real("y").notNull(),
    width: real("width").notNull(),
    height: real("height").notNull(),
    notes: text("notes").notNull(),
  },
  (table) => [index("regions_analysis_idx").on(table.analysisId)],
);

/** Evaluation-access requests captured by the closing CTA of the landing page. */
export const accessRequests = pgTable("access_requests", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  email: text("email").notNull(),
  organisation: text("organisation").notNull(),
  role: text("role").notNull(),
  message: text("message").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type AnalysisRow = typeof analyses.$inferSelect;
export type FindingRow = typeof findings.$inferSelect;
export type RegionRow = typeof regions.$inferSelect;
