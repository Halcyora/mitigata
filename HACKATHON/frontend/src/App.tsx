import { useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchGraph, graphQueryKey } from "./api";
import { CorrelationGraph } from "./components/CorrelationGraph";
import { useVerification } from "./hooks/useVerification";
import type { GraphNode, TargetId } from "./types";

const TARGETS: { id: TargetId; name: string; description: string }[] = [
  { id: "flask_demo", name: "Flask Demo", description: "Python · Flask" },
  { id: "juice_shop", name: "Juice Shop", description: "JavaScript · Express" },
];

function labelClass(label?: string | null) {
  if (label === "Confirmed") return "badge-confirmed";
  if (label === "Runtime only") return "badge-runtime";
  if (label === "Code only") return "badge-code";
  return "badge-muted";
}

function FindingDetail({
  finding,
  verifyState,
  onVerify,
}: {
  finding: GraphNode | undefined;
  verifyState: ReturnType<typeof useVerification>;
  onVerify: () => void;
}) {
  if (!finding) {
    return (
      <aside className="detail-panel detail-empty">
        <div className="detail-empty-icon">⌁</div>
        <h2>Finding details</h2>
        <p>Select a sink or evidence node in the graph to inspect its finding.</p>
      </aside>
    );
  }

  const { data } = finding;
  const canVerify = data.finding_label === "Code only";

  return (
    <aside className="detail-panel">
      <div className="detail-heading">
        <div>
          <span className="eyebrow">FINDING DETAIL</span>
          <h2>{data.cwe ?? "Security finding"}</h2>
        </div>
        {data.finding_label && (
          <span className={`status-badge ${labelClass(data.finding_label)}`}>
            {data.finding_label}
          </span>
        )}
      </div>
      <section className="detail-section">
        <h3>Location</h3>
        {data.file ? (
          <p className="code-location">
            <code>{data.file}</code>
            {data.line && <span>:{data.line}</span>}
          </p>
        ) : (
          <p className="muted-copy">No source location is available.</p>
        )}
        {data.confidence != null && (
          <div className="confidence-line">
            <span>Confidence</span>
            <strong>{Math.round(data.confidence * 100)}%</strong>
          </div>
        )}
      </section>
      <section className="detail-section">
        <h3>Evidence</h3>
        <pre className="evidence-block">
          {data.evidence || "No runtime evidence has been recorded."}
        </pre>
      </section>
      {canVerify && (
        <section className="verify-section">
          <button
            className="verify-button"
            type="button"
            onClick={onVerify}
            disabled={verifyState.status === "running"}
          >
            {verifyState.status === "running" ? (
              <>
                <span className="spinner" /> Verifying...
              </>
            ) : (
              "Verify at runtime"
            )}
          </button>
          {verifyState.label && (
            <p className="live-label">
              Live result{" "}
              <span className={`status-badge ${labelClass(verifyState.label)}`}>
                {verifyState.label}
              </span>
            </p>
          )}
          {verifyState.error && (
            <p className="error-copy" role="alert">{verifyState.error}</p>
          )}
          {verifyState.probeHistory.length > 0 && (
            <div className="probe-history">
              <h3>Probe history</h3>
              {verifyState.probeHistory.map((probe, index) => (
                <article className="probe-record" key={`${index}-${probe.variant}`}>
                  <div>
                    <strong>Attempt {index + 1}</strong>
                    {probe.status != null && <span>HTTP {probe.status}</span>}
                  </div>
                  {probe.payload && <code>{probe.payload}</code>}
                  {probe.response_preview && <p>{probe.response_preview}</p>}
                  {probe.error && <p className="error-copy">{probe.error}</p>}
                </article>
              ))}
            </div>
          )}
        </section>
      )}
    </aside>
  );
}

export default function App() {
  const [targetId, setTargetId] = useState<TargetId>("flask_demo");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const graphQuery = useQuery({
    queryKey: graphQueryKey(targetId),
    queryFn: () => fetchGraph(targetId),
  });
  const verification = useVerification(selectedFindingId, targetId);
  const selectedFinding = graphQuery.data?.nodes.find(
    (node) =>
      node.data.finding_id === selectedFindingId &&
      (node.type === "sink" || node.type === "suppressed"),
  );

  function changeTarget(value: TargetId) {
    setSelectedFindingId(null);
    setTargetId(value);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="Mitigata dashboard home">
          <span className="brand-mark">M</span>
          <span>mitigata<span className="brand-period">.</span></span>
        </a>
        <div className="topbar-right">
          <span className={`engine-status${graphQuery.isError ? " is-error" : ""}`}>
            <i />
            {graphQuery.isError
              ? "Engine unavailable"
              : graphQuery.isPending
                ? "Connecting..."
                : "Engine connected"}
          </span>
          <label className="target-select-wrap">
            <span className="sr-only">Select target</span>
            <select
              value={targetId}
              onChange={(event) => changeTarget(event.target.value as TargetId)}
            >
              {TARGETS.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} — {target.description}
                </option>
              ))}
            </select>
          </label>
        </div>
      </header>
      <section className="page-heading">
        <div>
          <p className="eyebrow">SECURITY POSTURE / CORRELATION</p>
          <h1>Attack path graph</h1>
          <p className="page-subtitle">
            Trace endpoints through application code to discovered evidence.
          </p>
        </div>
        <div className="target-chip">
          <span className="target-chip-dot" />
          {TARGETS.find((target) => target.id === targetId)?.name}
        </div>
      </section>

      {graphQuery.data && (
        <section className="stats-bar" aria-label="Finding statistics">
          <div className="stat-total">
            <span className="stat-value">{graphQuery.data.stats.total}</span>
            <span className="stat-label">Total findings</span>
          </div>
          <div className="stat-item">
            <span className="stat-dot confirmed" />
            <strong>{graphQuery.data.stats.confirmed}</strong>
            <span>Confirmed</span>
          </div>
          <div className="stat-item">
            <span className="stat-dot code" />
            <strong>{graphQuery.data.stats.code_only}</strong>
            <span>Code only</span>
          </div>
          <div className="stat-item">
            <span className="stat-dot runtime" />
            <strong>{graphQuery.data.stats.runtime_only}</strong>
            <span>Runtime only</span>
          </div>
          <div className="stat-item stat-suppression">
            <strong>
              {(graphQuery.data.stats.suppression_ratio * 100).toFixed(0)}%
            </strong>
            <span>Suppression ratio</span>
          </div>
          <div className="cwe-coverage">
            <strong>{graphQuery.data.stats.cwe_types_covered.length}</strong>
            <span>CWE types</span>
          </div>
        </section>
      )}

      {graphQuery.isPending ? (
        <div className="page-state">
          <span className="spinner" />
          <p>Loading target graph...</p>
        </div>
      ) : graphQuery.isError ? (
        <div className="page-state page-error" role="alert">
          <h2>Could not load correlation graph</h2>
          <p>{graphQuery.error.message}</p>
          <button type="button" onClick={() => void graphQuery.refetch()}>
            Retry
          </button>
        </div>
      ) : graphQuery.data ? (
        <section className="workspace">
          <div className="graph-panel">
            <div className="panel-title">
              <div>
                <span className="eyebrow">CORRELATION MAP</span>
                <h2>Routes &amp; findings</h2>
              </div>
              <span className="graph-count">
                {graphQuery.data.nodes.length} graph nodes
              </span>
            </div>
            <CorrelationGraph
              graph={graphQuery.data}
              onSelectFinding={setSelectedFindingId}
            />
          </div>
          <FindingDetail
            finding={selectedFinding}
            verifyState={verification}
            onVerify={verification.verify}
          />
        </section>
      ) : null}
    </main>
  );
}
