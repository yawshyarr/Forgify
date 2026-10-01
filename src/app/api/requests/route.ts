import { NextResponse } from "next/server";
import { db } from "@/db";
import { accessRequests } from "@/db/schema";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body" }, { status: 400 });
  }

  const str = (k: string) => (typeof body[k] === "string" ? (body[k] as string).trim() : "");
  const name = str("name");
  const email = str("email");
  const organisation = str("organisation");
  const role = str("role") || "evaluator";
  const message = str("message");

  if (name.length < 2) return NextResponse.json({ ok: false, error: "Please provide your name." }, { status: 422 });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email)) {
    return NextResponse.json({ ok: false, error: "Please provide a valid email address." }, { status: 422 });
  }

  try {
    const [row] = await db
      .insert(accessRequests)
      .values({ name, email, organisation: organisation || "—", role, message: message || "—" })
      .returning({ id: accessRequests.id });
    return NextResponse.json({ ok: true, id: row?.id, message: "Request recorded. The examiner workspace is open — no approval needed." });
  } catch (error) {
    console.error("[requests] insert failed", error);
    return NextResponse.json({ ok: false, error: "Could not record the request." }, { status: 500 });
  }
}
