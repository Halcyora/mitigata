import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  fetchLatestScan,
  fetchPlanner,
  fetchScanComparison,
  graphQueryKey,
  scanJobQueryKey,
  startScan,
} from "../api";
import type { ScanJob, TargetId } from "../types";

const ACTIVE_STATUSES = new Set(["SAST_RUNNING", "DAST_RUNNING"]);
const FINISHED_STATUSES = new Set(["SAST_COMPLETED", "COMPLETED", "INCOMPLETE", "FAILED"]);

function isActive(job: ScanJob | null | undefined) {
  return Boolean(job && ACTIVE_STATUSES.has(job.status));
}

export function PlannerPanel({ targetId }: { targetId: TargetId }) {
  const queryClient = useQueryClient();
  const [startError, setStartError] = useState<string | null>(null);
  const refreshedJobId = useRef<string | null>(null);
  const planQuery = useQuery({
    queryKey: ["planner", targetId],
    queryFn: () => fetchPlanner(targetId),
  });
  const jobQuery = useQuery({
    queryKey: scanJobQueryKey(targetId),
    queryFn: () => fetchLatestScan(targetId),
    refetchInterval: (query) => (isActive(query.state.data) ? 1000 : false),
  });
  const comparisonQuery = useQuery({
    queryKey: ["scan-comparison", targetId],
    queryFn: () => fetchScanComparison(targetId),
  });
  const startMutation = useMutation({
    mutationFn: (scanType: "sast" | "dast") => startScan(targetId, scanType),
    onSuccess: (job) => {
      setStartError(null);
      queryClient.setQueryData(scanJobQueryKey(targetId), job);
    },
    onError: (error: Error) => {
      setStartError(error.message);
      void queryClient.invalidateQueries({ queryKey: scanJobQueryKey(targetId) });
    },
  });

  const plan = planQuery.data;
  const job = jobQuery.data;
  const running = isActive(job) || startMutation.isPending;

  useEffect(() => {
    if (!job || !FINISHED_STATUSES.has(job.status) || refreshedJobId.current === job.job_id) {
      return;
    }
    refreshedJobId.current = job.job_id;
    void queryClient.invalidateQueries({ queryKey: graphQueryKey(targetId) });
    void queryClient.invalidateQueries({ queryKey: ["planner", targetId] });
    void queryClient.invalidateQueries({ queryKey: ["scan-comparison", targetId] });
  }, [job, queryClient, targetId]);

  if (planQuery.isPending) {
    return <section className="detail-section"><h3>Scan planner</h3><p>Loading scan plan...</p></section>;
  }
  if (planQuery.isError || !plan) {
    return <section className="detail-section"><h3>Scan planner</h3><p className="error-copy">{planQuery.error?.message ?? "Unable to load scan plan."}</p></section>;
  }

  const tasks = [...plan.targeted_tasks, ...plan.broad_tasks];
  return (
    <section className="detail-section planner-panel">
      <div className="panel-title">
        <div>
          <span className="eyebrow">SCAN EXECUTION</span>
          <h2>Planner &amp; model status</h2>
        </div>
      </div>

      <p>{plan.targeted_tasks.length} targeted · {plan.broad_tasks.length} broad fallback · {plan.unresolved_finding_ids.length} unresolved findings</p>
      <p>Bounded runtime verification is available for source findings. GraphCodeBERT ranks ambiguous route candidates for scan planning only; its score is advisory.</p>
      <p>GraphCodeBERT: {plan.code_intelligence.status} ({plan.code_intelligence.mode}) · {plan.code_intelligence.model_id}</p>
      <p>Model revision: {plan.code_intelligence.model_revision} · {plan.code_intelligence.preprocessor_version}</p>
      {plan.code_intelligence.status_detail && <p>{plan.code_intelligence.status_detail}</p>}
      {plan.intelligence_assessments.length > 0 && <div className="planner-task-list">
        {plan.intelligence_assessments.slice(0, 6).map((assessment) => <article key={assessment.assessment_id}>
          <strong>Finding {assessment.finding_id.slice(0, 8)} · route {assessment.candidate_route_id}</strong>
          <span>{assessment.status} · cosine similarity {assessment.relevance_score.toFixed(3)} · {assessment.score_calibration}</span>
          <small>{assessment.evidence_refs.map((ref) => `${ref.file}:${ref.start_line}-${ref.end_line}`).join(" · ") || assessment.limitations.join(" · ")}</small>
        </article>)}
      </div>}

      <div className="scan-controls">
        <p>Run SAST and DAST separately. DAST uses the saved SAST report, tests targeted routes first, then uses remaining budget for broad fallback.</p>
        <div className="scan-buttons">
          <button
            className="verify-button"
            type="button"
            disabled={running}
            onClick={() => {
              setStartError(null);
              startMutation.mutate("sast");
            }}
          >
            {job?.status === "SAST_RUNNING" ? "SAST running…" : "Run SAST"}
          </button>
          <button
            className="verify-button"
            type="button"
            disabled={running}
            onClick={() => {
              setStartError(null);
              startMutation.mutate("dast");
            }}
          >
            {job?.status === "DAST_RUNNING" ? "DAST running…" : "Run targeted + broad DAST"}
          </button>
        </div>
        <small>Run SAST first to scan its latest findings. DAST will report an error if no Semgrep report is available.</small>
        {startError && <p className="error-copy" role="alert">{startError}</p>}
        {job && <div className="scan-job-status" aria-live="polite">
          <strong>{job.scan_type.toUpperCase()} · {job.status} · {job.phase}</strong>
          <span>{job.message}</span>
          {job.phase === "DAST" && (job.status === "DAST_RUNNING" ? <span>
            {job.targeted_total} targeted · {job.broad_total} broad tasks planned
            {job.budget_minutes ? ` · ${job.budget_minutes} minute DAST budget` : ""}
          </span> : <span>
            Targeted {job.targeted_completed}/{job.targeted_total} · broad {job.broad_completed}/{job.broad_total}
            {job.cutoff ? " · budget cutoff" : ""}
          </span>)}
          {job.phase === "FINISHED" && job.scan_id && <span>
            Targeted {job.targeted_completed}/{job.targeted_total} · broad {job.broad_completed}/{job.broad_total}
            {job.cutoff ? " · budget cutoff" : ""}
          </span>}
          {job.scan_id && <small>Scan ID: {job.scan_id}</small>}
          {job.error && <pre className="evidence-block">{job.error}</pre>}
        </div>}
        {jobQuery.isError && <p className="error-copy">{jobQuery.error.message}</p>}
      </div>

      <p>Planned tasks (not execution status)</p>
      <div className="planner-task-list">
        {tasks.slice(0, 8).map((task) => <article key={task.task_id}>
          <strong>{task.phase} · {task.method} {task.normalized_url}</strong>
          <span>PLANNED · priority {task.priority_score}</span>
          <small>{task.reason_codes.join(" · ")}</small>
        </article>)}
      </div>
      <div className="scan-comparison">
        <h3>Scan comparison</h3>
        {comparisonQuery.isPending ? <p>Loading scan history…</p> : comparisonQuery.isError ? <p className="error-copy">{comparisonQuery.error.message}</p> : !comparisonQuery.data.available ? <p>{comparisonQuery.data.reason}</p> : <>
          <p>Comparing {comparisonQuery.data.previous?.scan_type?.toUpperCase()} with {comparisonQuery.data.current?.scan_type?.toUpperCase()}.</p>
          <div className="comparison-counts"><span><strong>{comparisonQuery.data.new?.length ?? 0}</strong> new</span><span><strong>{comparisonQuery.data.fixed?.length ?? 0}</strong> fixed</span><span><strong>{comparisonQuery.data.still_open?.length ?? 0}</strong> still open</span></div>
          {["new", "fixed", "still_open"].map((kind) => {
            const rows = comparisonQuery.data[kind as "new" | "fixed" | "still_open"] ?? [];
            return rows.length > 0 ? <details key={kind}><summary>{kind.replace("_", " ")} ({rows.length})</summary><ul>{rows.slice(0, 10).map((row, index) => <li key={`${String(row.key)}-${index}`}>{String(row.cwe ?? "Finding")} · {String(row.file ? `${row.file}:${row.line ?? ""}` : `${row.method ?? ""} ${row.url ?? ""}`)}</li>)}</ul></details> : null;
          })}
        </>}
      </div>
    </section>
  );
}
