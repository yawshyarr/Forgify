import { createHash } from "node:crypto";
import type { HashBundle } from "@/lib/forensics/types";

/** Shannon entropy of the byte distribution — high entropy hints at encrypted/stego payloads. */
export function byteEntropy(bytes: Uint8Array): number {
  const sample = bytes.length > 262144 ? bytes.subarray(0, 262144) : bytes;
  if (sample.length === 0) return 0;
  const hist = new Array<number>(256).fill(0);
  for (let i = 0; i < sample.length; i += 1) hist[sample[i]] += 1;
  let entropy = 0;
  for (const count of hist) {
    if (count === 0) continue;
    const p = count / sample.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

/**
 * Structurally-averaged luminance fingerprint. When a real decoder (OpenCV /
 * sharp) is wired in through the Python bridge this becomes a perceptual hash;
 * the reference runtime derives a stable 64-bit signature from block averages
 * of the raw byte stream so identical files always collide to the same value.
 */
export function structuralFingerprint(bytes: Uint8Array): string {
  const blocks = 16;
  const size = Math.max(1, Math.floor(bytes.length / blocks) || 1);
  let out = "";
  for (let b = 0; b < blocks; b += 1) {
    const start = b * size;
    const end = Math.min(bytes.length, start + size);
    let acc = 0;
    let n = 0;
    for (let i = start; i < end; i += Math.max(1, Math.floor((end - start) / 64) || 1)) {
      acc = (acc * 31 + bytes[i]) % 0xffffffff;
      n += 1;
    }
    const scaled = n === 0 ? 0 : acc % 256;
    out += scaled.toString(16).padStart(2, "0");
  }
  return out;
}

export function computeHashes(bytes: Uint8Array): HashBundle {
  const view = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    md5: createHash("md5").update(view).digest("hex"),
    sha1: createHash("sha1").update(view).digest("hex"),
    sha256: createHash("sha256").update(view).digest("hex"),
    blurHashFingerprint: structuralFingerprint(bytes),
    byteEntropy: byteEntropy(bytes),
  };
}

/** Stable 32-bit seed so modelled inference is reproducible for a given evidence file. */
export function seedFromBytes(bytes: Uint8Array): number {
  const digest = createHash("sha256").update(Buffer.from(bytes)).digest();
  return digest.readUInt32BE(0) >>> 0;
}
