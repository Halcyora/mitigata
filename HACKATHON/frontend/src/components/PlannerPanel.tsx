import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchPlanner } from "../api";
import type { TargetId } from "../types";

export function PlannerPanel({ targetId }: { targetId: TargetId }) {
  const [now, setNow] = useState(() => Date.now());
  const query = useQuery({ queryKey: ["planner", targetId], queryFn: () => fetchPlanner(targetId) });
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  if (query.isPending) return <section className="detail-section"><h3>Scan planner</h3><p>Loading planner state...</p></section>;
  if (query.isError) return <section className="detail-section"><h3>Scan planner</h3><p className="error-copy">{query.error.message}</p></section>;
  const plan = query.data;
  const remainingSeconds = Math.max(0, Math.ceil((Date.parse(plan.deadline_at) - now) / 1000));
  const tasks = [...plan.targeted_tasks, ...plan.broad_tasks];
  return (
    <section className="detail-section planner-panel">
      <div className="panel-title"><div><span className="eyebrow">SCAN EXECUTION</span><h2>Planner &amp; model status</h2></div></div>
      <p>{plan.targeted_tasks.length} targeted · {plan.broad_tasks.length} broad fallback · {plan.unresolved_finding_ids.length} unresolved findings</p>
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
      <p>Budget remaining: {Math.floor(remainingSeconds / 60)}m {remainingSeconds % 60}s · deadline {new Date(plan.deadline_at).toLocaleTimeString()}</p>
      <div className="planner-task-list">{tasks.slice(0, 8).map((task) => <article key={task.task_id}><strong>{task.phase} · {task.method} {task.normalized_url}</strong><span>{task.status} · priority {task.priority_score}</span><small>{task.reason_codes.join(" · ")}</small></article>)}</div>
    </section>
  );
}
