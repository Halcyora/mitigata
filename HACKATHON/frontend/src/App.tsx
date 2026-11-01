import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { fetchGraph, graphQueryKey, requestPatch, sarifCiGateUrl, sarifExportUrl } from "./api";
import { CorrelationGraph } from "./components/CorrelationGraph";
import { BusinessRiskPanel } from "./components/BusinessRiskPanel";
import { PlannerPanel } from "./components/PlannerPanel";
import { useVerification } from "./hooks/useVerification";
import type { GraphNode, TargetId } from "./types";

const TARGETS: { id: TargetId; name: string; description: string }[] = [
  { id: "flask_demo", name: "Flask Demo", description: "Python · Flask" },
  { id: "juice_shop", name: "Juice Shop", description: "JavaScript · Express" },
];

function labelClass(label?: string | null) {
  if (label === "Confirmed") return "badge-confirmed";
  if (label === "Corroborated") return "badge-corroborated";
  if (label === "Runtime only") return "badge-runtime";
  if (label === "Code only") return "badge-code";
  return "badge-muted";
}

function FindingDetail({
  finding,
  targetId,
  verification,
}: {
  finding: GraphNode | undefined;
  targetId: TargetId;
  verification: ReturnType<typeof useVerification>;
}) {
  const [patchState, setPatchState] = useState<{ patch: string; source: string; kind: string } | null>(null);
  const [patchError, setPatchError] = useState<string | null>(null);
  const [patchBusy, setPatchBusy] = useState(false);
  useEffect(() => {
    setPatchState(null);
    setPatchError(null);
  }, [finding?.data.finding_id]);
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
  const observedUrl = data.url && /^https?:\/\//i.test(data.url) ? data.url : null;
  const mappedUrl = data.mapped_urls?.[0] ?? data.routes?.find((route) => route.startsWith("/"));
  const endpointUrl = observedUrl ?? mappedUrl ?? data.url;
  const endpointDescription = observedUrl
    ? "Observed request URL"
    : data.finding_label === "Confirmed" && data.evidence
      ? "Verified probe route"
      : mappedUrl
        ? "Mapped endpoint · not probed"
        : "No endpoint mapped to this source location";

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
        <div className="finding-facts">
          <span><small>Severity</small><strong className={`severity-${(data.severity ?? "medium").toLowerCase()}`}>{data.severity ?? "Unknown"}</strong></span>
          <span><small>Scanner</small><strong>{data.source?.toUpperCase() ?? "—"}</strong></span>
          {data.function && <span><small>Function</small><strong><code>{data.function}</code></strong></span>}
        </div>
        {data.source_snippet && <div className="source-preview">
          <div className="source-preview-heading"><span>Source context</span><code>{data.file}:{data.line}</code></div>
          <pre>{data.source_snippet.split("\n").map((row) => {
            const match = /^(\d+): ?(.*)$/.exec(row);
            const isHot = Number(match?.[1]) === data.line;
            return <span className={isHot ? "source-line is-vulnerable" : "source-line"} key={row}><i>{match?.[1]}</i><code>{match?.[2]}</code></span>;
          })}</pre>
        </div>}
        {data.confidence != null && (
          <div className="confidence-line">
            <span>Confidence</span>
            <strong>{Math.round(data.confidence * 100)}%</strong>
          </div>
        )}
      </section>
      {data.routes && data.routes.length > 0 && (
        <section className="detail-section">
          <h3>{data.source === "sast" ? "Mapped routes" : "Observed routes"}</h3>
          <ul>{data.routes.map((route) => <li key={route}><code>{route}</code></li>)}</ul>
        </section>
      )}
      {data.merged_from && data.merged_from.length > 0 && (
        <section className="detail-section"><h3>Correlation explanation</h3><p>{data.reason ?? "Code and runtime evidence were correlated."}</p><ul>{data.merged_from.map((id) => <li key={id}><code>{id}</code></li>)}</ul></section>
      )}
      {data.remediation && <section className="detail-section"><h3>Suggested fix</h3><p>{data.remediation}</p></section>}
      {data.file && data.line && data.finding_id && (
        <section className="detail-section"><h3>Remediation suggestion</h3><p className="muted-copy">Sarvam generates a bounded patch preview from this source context. If unavailable or rejected, Mitigata returns a local sink template or CWE-specific guidance.</p><button className="verify-button" type="button" disabled={patchBusy} onClick={async () => { setPatchBusy(true); setPatchError(null); try { const result = await requestPatch(data.finding_id!, targetId); setPatchState({ patch: result.patch, source: result.source, kind: result.kind }); } catch (error) { setPatchError(error instanceof Error ? error.message : "Patch generation failed"); } finally { setPatchBusy(false); } }}>{patchBusy ? "Generating suggestion…" : "Generate Sarvam fix suggestion"}</button>{patchError && <p className="error-copy">{patchError}</p>}{patchState && <><p className="provider-chip">Suggestion provider <strong>{patchState.source === "sarvam" ? "Sarvam API" : "Local deterministic guidance"}</strong> · {patchState.kind === "unified_diff" ? "validated diff" : patchState.kind === "guidance" ? "remediation guidance" : "snippet preview"}</p><pre className="evidence-block">{patchState.patch}</pre></>}</section>
      )}
      <section className="detail-section">
        <h3>HTTP trace</h3>
        <div className="http-trace">
          <strong>{data.method ?? (observedUrl ? "HTTP" : "Mapped")} {endpointUrl ?? "Endpoint unavailable"}</strong>
          <span>{endpointDescription}</span>
          {data.parameter && <span>Input: <code>{data.parameter}</code> ({data.parameter_source ?? "source unknown"})</span>}
          {data.http_status != null && <span>Response status: {data.http_status}</span>}
          {data.payload && <span>Probe payload: <code>{data.payload}</code></span>}
        </div>
        {data.evidence_items && data.evidence_items.length > 0 && <>
          <h3 className="evidence-title">Merged scanner evidence ({data.evidence_items.length})</h3>
          <div className="scanner-evidence-list">{data.evidence_items.map((item, index) => <article key={`${String(item.alert_id ?? item.source ?? "evidence")}-${index}`}>
            <strong>{String(item.source ?? "Scanner evidence")}{item.alert_id ? ` · ${String(item.alert_id)}` : ""}</strong>
            {Boolean(item.rule_id) && <span>Rule: <code>{String(item.rule_id)}</code></span>}
            {Boolean(item.file) && <span>Location: <code>{String(item.file)}{item.line ? `:${String(item.line)}` : ""}</code></span>}
            {Boolean(item.method) && Boolean(item.url) && <code>{String(item.method)} {String(item.url)}</code>}
            {Boolean(item.parameter) && <span>Input: <code>{String(item.parameter)}</code></span>}
            {Boolean(item.payload) && <span>Payload: <code>{String(item.payload)}</code></span>}
            {item.http_status != null && <span>Status: {String(item.http_status)}</span>}
            {Boolean(item.evidence) && <p>{String(item.evidence)}</p>}
            {Boolean(item.snippet) && <pre className="evidence-block">{String(item.snippet)}</pre>}
          </article>)}</div>
        </>}
        <h3 className="evidence-title">Runtime evidence</h3>
        <pre className="evidence-block">
          {data.evidence || "No runtime evidence has been recorded."}
        </pre>
      </section>
      {data.source === "sast" && data.finding_label !== "Confirmed" && data.finding_id && <section className="detail-section">
        <h3>Runtime verification</h3>
        <p className="muted-copy">Run a bounded, target-scoped probe using this finding’s mapped route and input.</p>
        <button className="verify-button" type="button" disabled={verification.status === "running"} onClick={verification.verify}>
          {verification.status === "running" ? "Verifying…" : "Verify against target"}
        </button>
        {verification.label && <p className="verification-result">Result: <strong>{verification.label}</strong></p>}
        {verification.error && <p className="error-copy">{verification.error}</p>}
        {verification.probeHistory.length > 0 && <div className="probe-history">{verification.probeHistory.map((probe, index) => <article key={`${probe.route ?? "probe"}-${index}`}>
          <strong>{probe.method ?? "Probe"} {probe.route ?? ""}</strong>
          {probe.parameter && <span>{probe.parameter_source ?? "input"}: <code>{probe.parameter}</code></span>}
          {probe.payload && <span>Payload: <code>{probe.payload}</code></span>}
          {probe.status != null && <span>HTTP {probe.status}</span>}
          {probe.response_preview && <pre className="evidence-block">{probe.response_preview}</pre>}
          {probe.error && <span className="error-copy">{probe.error}</span>}
        </article>)}</div>}
      </section>}
      {data.risk_score != null && <div className="confidence-line risk-score-line" title="Severity plus runtime proof, route reachability, request-input evidence, and captured evidence.">
        <span>Priority score <small>(severity + exploitability)</small></span><strong>{data.risk_score}/100</strong>
      </div>}
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
  const [search, setSearch] = useState("");
  const [labelFilter, setLabelFilter] = useState("All statuses");
  const [severityFilter, setSeverityFilter] = useState("All severities");
  const [view, setView] = useState<"issues" | "graph">("issues");
  const [ciGateState, setCiGateState] = useState<{ busy: boolean; message: string | null; passed?: boolean }>({ busy: false, message: null });
  const findings = useMemo(() => {
    const all = (graphQuery.data?.nodes ?? []).filter((node) => node.type === "sink" || node.type === "suppressed");
    const query = search.trim().toLowerCase();
    return all.filter(({ data }) => {
      const matchesText = !query || [data.label, data.cwe, data.file, data.url, data.function, data.sink_type].some((value) => String(value ?? "").toLowerCase().includes(query));
      return matchesText && (labelFilter === "All statuses" || data.finding_label === labelFilter) && (severityFilter === "All severities" || (data.severity ?? "Unknown").toUpperCase() === severityFilter.toUpperCase());
    });
  }, [graphQuery.data, search, labelFilter, severityFilter]);

  function changeTarget(value: TargetId) {
    setSelectedFindingId(null);
    setTargetId(value);
  }

  async function runCiGate() {
    setCiGateState({ busy: true, message: null });
    try {
      const response = await fetch(sarifCiGateUrl(targetId));
      if (!response.ok && response.status !== 409) {
        throw new Error(`CI gate request failed (${response.status})`);
      }
      const sarif = await response.blob();
      const objectUrl = URL.createObjectURL(sarif);
      const download = document.createElement("a");
      download.href = objectUrl;
      download.download = `mitigata-${targetId}-ci-gate.sarif`;
      download.click();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1_000);
      setCiGateState({
        busy: false,
        passed: response.status !== 409,
        message: response.status === 409
          ? "CI gate failed: confirmed high or critical findings were found. SARIF downloaded."
          : "CI gate passed: no confirmed high or critical findings. SARIF downloaded.",
      });
    } catch (error) {
      setCiGateState({ busy: false, message: error instanceof Error ? error.message : "CI gate request failed." });
    }
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
          <h1>Application security findings</h1>
          <p className="page-subtitle">
            One prioritized view of source findings, runtime proof, and fixes.
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
            <span className="stat-dot corroborated" />
            <strong>{graphQuery.data.stats.corroborated}</strong>
            <span>Corroborated</span>
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

      {graphQuery.data && <div className="view-toolbar">
        <div className="view-switch" role="tablist" aria-label="Dashboard view">
          <button role="tab" aria-selected={view === "issues"} className={view === "issues" ? "active" : ""} onClick={() => setView("issues")}>Issue queue</button>
          <button role="tab" aria-selected={view === "graph"} className={view === "graph" ? "active" : ""} onClick={() => setView("graph")}>Attack path graph</button>
        </div>
        <div className="export-actions"><a className="export-button" href={sarifExportUrl(targetId)}>Export SARIF <span>↓</span></a><button className="export-button" type="button" onClick={runCiGate} disabled={ciGateState.busy}>{ciGateState.busy ? "Checking CI gate…" : "Run CI gate · confirmed high"}</button></div>
      </div>}
      {ciGateState.message && <p className={`ci-gate-result${ciGateState.passed === false ? " failed" : ciGateState.passed ? " passed" : ""}`} role="status">{ciGateState.message}</p>}

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
        <section className={`workspace ${view === "issues" ? "issues-workspace" : "graph-workspace"}`}>
          {view === "issues" && <div className="issue-queue">
            <div className="panel-title"><div><span className="eyebrow">PRIORITIZED QUEUE</span><h2>Findings <span className="queue-count">{findings.length}</span></h2></div></div>
            <div className="queue-filters"><input aria-label="Search findings" placeholder="Search CWE, route, file…" value={search} onChange={(event) => setSearch(event.target.value)} /><select value={labelFilter} onChange={(event) => setLabelFilter(event.target.value)}><option>All statuses</option><option>Confirmed</option><option>Corroborated</option><option>Code only</option><option>Runtime only</option></select><select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option>All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select></div>
            <div className="issue-list">{findings.map(({ id, data }) => <button type="button" key={id} className={`issue-row${data.finding_id === selectedFindingId ? " selected" : ""}`} onClick={() => setSelectedFindingId(data.finding_id ?? null)}><div className="issue-row-top"><span className={`status-badge ${labelClass(data.finding_label)}`}>{data.finding_label ?? "Unclassified"}</span><span className={`severity-tag severity-${(data.severity ?? "medium").toLowerCase()}`}>{data.severity ?? "Medium"} · {data.risk_score ?? "—"}/100</span></div><strong>{data.cwe ?? "Security finding"} <span>{data.sink_type?.replaceAll("_", " ") ?? data.label}</span></strong><span className="issue-location">{data.file ? `${data.file}${data.line ? `:${data.line}` : ""}` : data.method && data.url ? `${data.method} ${data.url}` : "Source location unavailable"}</span><span className="issue-route">{data.url ?? data.routes?.join(", ") ?? "Route not mapped"}</span>{(data.evidence_items?.length ?? 0) > 0 && <span className="issue-evidence-count">{data.evidence_items?.length} evidence records merged</span>}</button>)}{findings.length === 0 && <p className="empty-queue">No findings match these filters.</p>}</div>
          </div>}
          <div className="graph-panel">
            <div className="panel-title">
              <div>
                <span className="eyebrow">{view === "issues" ? "SELECTED FINDING" : "CORRELATION MAP"}</span>
                <h2>{view === "issues" ? "Evidence & remediation" : "Routes & findings"}</h2>
              </div>
              <span className="graph-count">
                {view === "issues" ? `${findings.length} visible issues` : `${graphQuery.data.nodes.length} graph nodes`}
              </span>
            </div>
            {view === "graph" ? <CorrelationGraph graph={graphQuery.data} onSelectFinding={setSelectedFindingId} /> : <FindingDetail finding={selectedFinding} targetId={targetId} verification={verification} />}
          </div>
          {view === "graph" && <FindingDetail
            finding={selectedFinding}
            targetId={targetId}
            verification={verification}
          />}
        </section>
      ) : null}
      {graphQuery.data && <section className="supplemental-panels"><BusinessRiskPanel targetId={targetId} /><PlannerPanel targetId={targetId} /></section>}
    </main>
  );
}
