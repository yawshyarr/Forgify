/** Deterministic PRNG utilities shared by every modelled-inference adapter. */

export type Rng = () => number;

/** mulberry32 — tiny, fast, fully deterministic. */
export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export const clamp = (v: number, min = 0, max = 1) => Math.min(max, Math.max(min, v));

export const round = (v: number, digits = 3) => {
  const f = 10 ** digits;
  return Math.round(v * f) / f;
};

export function pick<T>(rand: Rng, items: readonly T[]): T {
  return items[Math.floor(rand() * items.length) % items.length];
}

/** Centered pseudo-Gaussian in [-1, 1] — smooths the crude uniform generator. */
export function jitter(rand: Rng, magnitude = 0.15): number {
  const a = rand();
  const b = rand();
  return ((a + b) / 2 - 0.5) * 2 * magnitude;
}

export function inRange(rand: Rng, min: number, max: number): number {
  return min + rand() * (max - min);
}

export function hex(rand: Rng, length: number): string {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += Math.floor(rand() * 16).toString(16);
  }
  return out;
}
