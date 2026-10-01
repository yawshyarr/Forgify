import type { AnalysisReport } from "@/lib/forensics/types";

/**
 * HTTP bridge to the Python/OpenCV inference service.
 *
 * Set `FORENSICS_ENGINE_URL` (e.g. http://127.0.0.1:8000) and every analysis
 * request is forwarded to the FastAPI worker in /python, which runs the real
 * cv2 / numpy / transformers implementations. If the worker is unreachable the
 * caller transparently falls back to the TypeScript reference runtime, so the
 * product never shows a dead dashboard during a demo.
 */
export async function analyzeRemote(
  input: { bytes: Uint8Array; name: string; mimeType: string; reference?: { bytes: Uint8Array; name: string; mimeType: string } | null },
  baseUrl: string,
): Promise<AnalysisReport | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 60_000);
  try {
    const form = new FormData();
    const view = new Uint8Array(input.bytes);
    form.append("file", new Blob([new Uint8Array(view)], { type: input.mimeType || "application/octet-stream" }), input.name);
    if (input.reference) {
      const rview = new Uint8Array(input.reference.bytes);
      form.append(
        "reference",
        new Blob([new Uint8Array(rview)], { type: input.reference.mimeType || "application/octet-stream" }),
        input.reference.name,
      );
    }
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/analyze`, {
      method: "POST",
      body: form,
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const json = (await res.json()) as Partial<AnalysisReport>;
    if (!json?.verdict || typeof json.verdict.riskScore !== "number" || !Array.isArray(json.layers)) return null;
    return { ...json, engine: { ...json.engine!, backend: "python-fastapi" } } as AnalysisReport;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

export function bridgeUrl(): string | null {
  return process.env.FORENSICS_ENGINE_URL?.trim() || null;
}
