export type TargetId = "flask_demo" | "juice_shop";
export type FindingLabel = "Confirmed" | "Code only" | "Runtime only";
export type GraphNodeType =
  | "endpoint"
  | "controller"
  | "sink"
  | "evidence"
  | "suppressed";

export interface GraphNodeData {
  label: string;
  target_id: TargetId;
  finding_id?: string | null;
  finding_label?: FindingLabel | null;
  confidence?: number | null;
  file?: string | null;
  line?: number | null;
  cwe?: string | null;
  evidence?: string | null;
}

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  position: { x: number; y: number };
  data: GraphNodeData;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  animated?: boolean;
}

export interface GraphStats {
  target_id: TargetId;
  total: number;
  confirmed: number;
  code_only: number;
  runtime_only: number;
  suppression_ratio: number;
  cwe_types_covered: string[];
}

export interface GraphResponse {
  target_id: TargetId;
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
}

export interface ProbeRecord {
  variant?: number;
  payload?: string;
  status?: number;
  response_preview?: string;
  error?: string;
}

export interface VerificationEvent {
  finding_id: string;
  target_id: TargetId;
  label?: FindingLabel | "UNVERIFIED";
  probe_history?: ProbeRecord[];
  evidence?: string | null;
  error?: string;
  done: boolean;
}
