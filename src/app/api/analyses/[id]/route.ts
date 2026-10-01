import { NextResponse } from "next/server";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { analyses } from "@/db/schema";

export const dynamic = "force-dynamic";

export async function GET(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ ok: false, error: "Invalid case id" }, { status: 400 });
  try {
    const [row] = await db.select().from(analyses).where(eq(analyses.id, id)).limit(1);
    if (!row) return NextResponse.json({ ok: false, error: "Case not found" }, { status: 404 });
    return NextResponse.json({ ok: true, report: row.report, assetDataUrl: row.assetDataUrl });
  } catch (error) {
    console.error("[analyses] fetch failed", error);
    return NextResponse.json({ ok: false, error: "Case lookup failed" }, { status: 500 });
  }
}

export async function DELETE(_request: Request, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) return NextResponse.json({ ok: false, error: "Invalid case id" }, { status: 400 });
  try {
    await db.delete(analyses).where(eq(analyses.id, id));
    return NextResponse.json({ ok: true });
  } catch (error) {
    console.error("[analyses] delete failed", error);
    return NextResponse.json({ ok: false, error: "Delete failed" }, { status: 500 });
  }
}
