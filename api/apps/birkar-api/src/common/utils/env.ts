// src/common/utils/env.ts
export function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

export function envString(name: string, fallback: string): string {
  const raw = process.env[name];
  return raw && raw.trim() ? raw.trim() : fallback;
}
