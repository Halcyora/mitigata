export type TargetId = "flask_demo" | "juice_shop";
export type FindingLabel = "Confirmed" | "Code only" | "Runtime only";
export type GraphNodeType =
  | "endpoint"
  | "controller"
  | "sink"
  | "evidence"
  | "suppressed";

export interface GraphNodeData {
  [key: string]: unknown;
  label: string;
  target_id: TargetId;
  finding_id?: string | null;
  finding_label?: FindingLabel | null;
  confidence?: number | null;
  file?: string | null;
  line?: number | null;
  cwe?: string | null;
  evidence?: string | null;
  merged_from?: string[];
  reason?: string | null;
  url?: string | null;
  method?: string | null;
  parameter?: string | null;
  parameter_source?: string | null;
  http_status?: number | null;
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

export interface ComplianceResponse {
  target_id: TargetId;
  records_at_risk: number;
  findings: Array<Record<string, unknown>>;
  summary: Record<string, number>;
}

export interface ScanTask {
  task_id: string;
  normalized_url: string;
  method: string;
  phase: string;
  priority_score: number;
  reason_codes: string[];
  status: string;
}

export interface CodeContextAssessment {
  assessment_id: string;
  finding_id: string;
  candidate_route_id: string;
  status: string;
  relevance_score: number;
  score_calibration: string;
  limitations: string[];
  evidence_refs: Array<{ file: string; start_line: number; end_line: number; function: string }>;
}

export interface ScanPlan {
  scan_id: string;
  deadline_at: string;
  targeted_tasks: ScanTask[];
  broad_tasks: ScanTask[];
  unresolved_finding_ids: string[];
  code_intelligence: {
    mode: string;
    status: string;
    model_id: string;
    model_revision: string;
    task_head_version: string;
    preprocessor_version: string;
    status_detail?: string;
  };
  intelligence_assessments: CodeContextAssessment[];
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
