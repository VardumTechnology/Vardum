// Deno KV — the relay's store (built into the runtime, zero-config).
// Phase 1: single KV namespace. Phase 2: swap for Postgres/Mongo behind the
// same helper functions if scale demands it — nothing else changes.
// b70 (re-review): say loudly when no database path is set — Deno's default
// location is easy to lose track of on a server
if (!Deno.env.get("VEIL_KV_PATH")) console.warn("[veil-relay] VEIL_KV_PATH is not set — using Deno's default KV location");
export const KV = await Deno.openKv(Deno.env.get("VEIL_KV_PATH") || undefined);
