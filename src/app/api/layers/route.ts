import { NextResponse } from "next/server";
import { LAYERS } from "@/lib/forensics/registry";
import { MODULES } from "@/lib/forensics/modules";

export const dynamic = "force-dynamic";

/** Public contract of the forensic engine — consumed by the landing page and by integrators. */
export async function GET() {
  return NextResponse.json({
    ok: true,
    engine: { name: "Forgify Forensic Engine", version: "2.4.0", modules: MODULES.length },
    layers: LAYERS.map((l) => {
      const mod = MODULES.find((m) => m.id === l.id);
      return {
        id: l.id,
        name: l.name,
        short: l.short,
        category: l.category,
        weight: l.weight,
        tagline: l.tagline,
        description: l.description,
        techniques: l.techniques,
        runtime: mod?.runtime ?? "n/a",
        executionMode: mod?.mode ?? "modelled",
      };
    }),
    endpoints: {
      analyze: "POST /api/analyze (multipart: file, optional reference)",
      cases: "GET /api/analyses?limit=&offset=&verdict=&q=",
      case: "GET /api/analyses/:id",
      layers: "GET /api/layers",
      health: "GET /api/health",
    },
  });
}
