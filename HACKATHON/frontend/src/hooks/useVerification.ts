import { useCallback, useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";

import { graphQueryKey, verificationStreamUrl } from "../api";
import type {
  FindingLabel,
  GraphResponse,
  ProbeRecord,
  TargetId,
  VerificationEvent,
} from "../types";

type VerificationStatus = "idle" | "running" | "done" | "error";

function isFindingLabel(value: string): value is FindingLabel {
  return (
    value === "Confirmed" || value === "Code only" || value === "Runtime only"
  );
}

export function useVerification(findingId: string | null, targetId: TargetId) {
  const queryClient = useQueryClient();
  const sourceRef = useRef<EventSource | null>(null);
  const [label, setLabel] = useState<FindingLabel | "UNVERIFIED" | null>(null);
  const [probeHistory, setProbeHistory] = useState<ProbeRecord[]>([]);
  const [status, setStatus] = useState<VerificationStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(
    () => () => {
      sourceRef.current?.close();
    },
    [findingId, targetId],
  );

  const verify = useCallback(() => {
    if (!findingId || status === "running") return;
    sourceRef.current?.close();
    setLabel(null);
    setProbeHistory([]);
    setError(null);
    setStatus("running");

    const source = new EventSource(verificationStreamUrl(findingId, targetId));
    sourceRef.current = source;
    source.onmessage = (message) => {
      let event: VerificationEvent;
      try {
        event = JSON.parse(message.data) as VerificationEvent;
      } catch {
        setError("The engine returned an invalid verification event.");
        setStatus("error");
        source.close();
        return;
      }
      if (event.target_id !== targetId || event.finding_id !== findingId) {
        return;
      }
      if (event.label) setLabel(event.label);
      if (event.probe_history) setProbeHistory(event.probe_history);
      if (event.error) setError(event.error);

      queryClient.setQueryData<GraphResponse>(
        graphQueryKey(targetId),
        (current) => {
          if (!current || !event.label || !isFindingLabel(event.label)) {
            return current;
          }
          const nodes = current.nodes.map((node) =>
            node.data.finding_id === findingId
              ? {
                  ...node,
                  data: { ...node.data, finding_label: event.label },
                }
              : node,
          );
          const labels = nodes
            .filter(
              (node) =>
                (node.type === "sink" || node.type === "suppressed") &&
                node.data.finding_id,
            )
            .map((node) => node.data.finding_label);
          return {
            ...current,
            nodes,
            stats: {
              ...current.stats,
              confirmed: labels.filter((value) => value === "Confirmed").length,
              code_only: labels.filter((value) => value === "Code only").length,
              runtime_only: labels.filter((value) => value === "Runtime only")
                .length,
            },
          };
        },
      );
      if (event.done) {
        setStatus(event.error ? "error" : "done");
        source.close();
      }
    };
    source.addEventListener("verification-error", (message) => {
      const event = message as MessageEvent<string>;
      try {
        const payload = JSON.parse(event.data) as VerificationEvent;
        setError(payload.error ?? "Verification failed.");
      } catch {
        setError("Verification failed; check the engine logs.");
      }
      setStatus("error");
      source.close();
    });
    source.onerror = () => {
      if (source.readyState !== EventSource.CLOSED) {
        setError("The verification stream was interrupted.");
        setStatus("error");
      }
      source.close();
    };
  }, [findingId, queryClient, status, targetId]);

  return { label, probeHistory, status, error, verify };
}
