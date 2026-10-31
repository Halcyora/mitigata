import type { GraphResponse, TargetId } from "./types";

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
