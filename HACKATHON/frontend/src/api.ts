import type { ComplianceResponse, GraphResponse, ScanPlan, TargetId } from "./types";

const apiBaseUrl = (
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000"
).replace(/\/+$/, "");

export function graphQueryKey(targetId: TargetId) {
  return ["graph", targetId] as const;
}

export async function fetchGraph(targetId: TargetId): Promise<GraphResponse> {
  const response = await fetch(
    `${apiBaseUrl}/api/graph?target_id=${encodeURIComponent(targetId)}`,
  );
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new Error(
      body?.detail ??
        `Unable to load graph (${response.status} ${response.statusText})`,
    );
  }
  return response.json() as Promise<GraphResponse>;
}

export function verificationStreamUrl(
  findingId: string,
  targetId: TargetId,
): string {
  return `${apiBaseUrl}/api/verify/${encodeURIComponent(findingId)}/stream?target_id=${encodeURIComponent(targetId)}`;
}

export async function fetchCompliance(targetId: TargetId): Promise<ComplianceResponse> {
  const response = await fetch(`${apiBaseUrl}/api/compliance?target_id=${encodeURIComponent(targetId)}`);
  if (!response.ok) throw new Error(`Compliance request failed (${response.status})`);
  return response.json() as Promise<ComplianceResponse>;
}

export async function fetchPlanner(targetId: TargetId): Promise<ScanPlan> {
  const response = await fetch(`${apiBaseUrl}/api/planner?target_id=${encodeURIComponent(targetId)}`);
  if (!response.ok) throw new Error(`Planner request failed (${response.status})`);
  return response.json() as Promise<ScanPlan>;
}

export async function requestPatch(findingId: string, targetId: TargetId): Promise<{ patch: string; kind: string; source: string; file: string }> {
  const response = await fetch(`${apiBaseUrl}/api/patch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId, target_id: targetId }),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.detail ?? `Patch request failed (${response.status})`);
  return body;
}

export async function applyPatch(findingId: string, targetId: TargetId, patch: string): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/api/patch/apply`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ finding_id: findingId, target_id: targetId, patch }),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.detail ?? `Patch apply failed (${response.status})`);
}
