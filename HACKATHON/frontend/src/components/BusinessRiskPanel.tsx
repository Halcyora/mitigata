import { useQuery } from "@tanstack/react-query";

import { fetchCompliance } from "../api";
import type { TargetId } from "../types";

const FRAMEWORKS: Record<string, string> = {
  rbi_csf: "RBI CSF",
  sebi_cscrf: "SEBI CSCRF",
  iso_27001: "ISO 27001",
  dpdp_2023: "DPDP Act 2023",
};

export function BusinessRiskPanel({ targetId }: { targetId: TargetId }) {
  const query = useQuery({ queryKey: ["compliance", targetId], queryFn: () => fetchCompliance(targetId) });
  if (query.isPending) return <section className="detail-section"><h3>Business risk &amp; compliance</h3><p>Loading...</p></section>;
  if (query.isError) return <section className="detail-section"><h3>Business risk &amp; compliance</h3><p className="error-copy">{query.error.message}</p></section>;

  const mapped = query.data.findings.find((finding) => finding.compliance && typeof finding.compliance === "object");
  const mappings = (mapped?.compliance ?? {}) as Record<string, string>;
  const risk = (mapped?.risk ?? {}) as Record<string, unknown>;
  return (
    <section className="detail-section business-risk">
      <h3>Business risk &amp; compliance</h3>
      <div className="risk-amount">{String(risk.total_exposure_formatted ?? "₹0")}</div>
      <p className="muted-copy">Estimated exposure for {query.data.records_at_risk.toLocaleString()} records · {String(risk.breach_probability_pct ?? 0)}% modelled probability</p>
      <p className="muted-copy">Cyber insurance threshold: {risk.cyber_insurance_impact ? "exceeded" : "not exceeded"}</p>
      {Object.entries(FRAMEWORKS).map(([key, name]) => (
        <div className="framework-row" key={key}><strong>{name}</strong><span>{mappings[key] ?? "Mapped controls are available per finding."}</span></div>
      ))}
      <p className="muted-copy">Reference: {String((risk.inc06_reference as Record<string, unknown> | undefined)?.incident ?? "2017 Credit Bureau Breach")} · IBM Cost of a Data Breach 2024 India benchmark</p>
    </section>
  );
}
