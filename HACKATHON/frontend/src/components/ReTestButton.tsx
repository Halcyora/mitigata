export function ReTestButton({ onClick, busy }: { onClick: () => void; busy: boolean }) {
  return <button className="verify-button" type="button" onClick={onClick} disabled={busy}>{busy ? <><span className="spinner" /> Verifying...</> : "Verify at runtime"}</button>;
}
