import "dotenv/config";

const engineUrl = process.env.FORENSICS_ENGINE_URL?.trim();
const banner = "!".repeat(76);

if (!engineUrl) {
  console.warn(`\n${banner}`);
  console.warn("FORENSICS ENGINE WARNING: FORENSICS_ENGINE_URL is not configured.");
  console.warn("The frontend will fall back to the TypeScript reference engine.");
  console.warn(banner + "\n");
} else {
  const healthUrl = `${engineUrl.replace(/\/$/, "")}/health`;
  try {
    const response = await fetch(healthUrl, { signal: AbortSignal.timeout(3_000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    console.info(`FORENSICS ENGINE READY: ${healthUrl}`);
  } catch (error) {
    console.warn(`\n${banner}`);
    console.warn(`FORENSICS ENGINE WARNING: ${healthUrl} is unreachable (${error.message}).`);
    console.warn("The frontend will fall back to the TypeScript reference engine.");
    console.warn(banner + "\n");
  }
}
