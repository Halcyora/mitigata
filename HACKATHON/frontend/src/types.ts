export type TargetId = "flask_demo" | "juice_shop";
export type FindingLabel = "Confirmed" | "Corroborated" | "Code only" | "Runtime only";
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
  routes?: string[];
  mapped_urls?: string[];
  cwe?: string | null;
  evidence?: string | null;
  evidence_items?: Array<Record<string, unknown>>;
  payload?: string | null;
  risk_score?: number | null;
  merged_from?: string[];
  reason?: string | null;
  url?: string | null;
  method?: string | null;
  parameter?: string | null;
  parameter_source?: string | null;
  http_status?: number | null;
  severity?: string | null;
  source?: string | null;
  source_snippet?: string | null;
  sink_type?: string | null;
  function?: string | null;
  remediation?: string | null;
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
  corroborated: number;
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

export interface ScanJob {
  job_id: string;
  target_id: TargetId;
  scan_type: "sast" | "dast";
  status: "SAST_RUNNING" | "DAST_RUNNING" | "SAST_COMPLETED" | "COMPLETED" | "INCOMPLETE" | "FAILED";
  phase: "SAST" | "DAST" | "FINISHED";
  message: string;
  started_at: string;
  finished_at: string | null;
  scan_id: string | null;
  budget_minutes: number | null;
  targeted_total: number;
  targeted_completed: number;
  broad_total: number;
  broad_completed: number;
  cutoff: boolean;
  error: string | null;
}

export interface ScanComparison {
  target_id: TargetId;
  available: boolean;
  reason?: string;
  previous?: { scan_id?: string; scan_type?: string; finished_at?: string };
  current?: { scan_id?: string; scan_type?: string; finished_at?: string };
  new?: Array<Record<string, unknown>>;
  fixed?: Array<Record<string, unknown>>;
  still_open?: Array<Record<string, unknown>>;
}

export interface ProbeRecord {
  variant?: number;
  payload?: string;
  status?: number;
  response_preview?: string;
  error?: string;
  route?: string;
  method?: string;
  parameter?: string;
  parameter_source?: string;
  location?: string;
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
