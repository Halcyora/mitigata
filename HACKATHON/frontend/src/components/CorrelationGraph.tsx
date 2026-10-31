import { useEffect, useMemo, useState } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import ELK from "elkjs/lib/elk.bundled.js";

import type {
  GraphNode,
  GraphNodeData,
  GraphResponse,
  GraphNodeType,
} from "../types";

type FlowNode = Node<GraphNodeData, GraphNodeType>;

const elk = new ELK();

function CorrelationNode({ data, type, selected }: NodeProps<FlowNode>) {
  const label = data.finding_label;
  const tone =
    type === "suppressed"
      ? "suppressed"
      : label === "Confirmed"
        ? "confirmed"
        : label === "Runtime only"
          ? "runtime"
          : label === "Code only"
            ? "code"
            : type;

  return (
    <div className={`graph-node node-${tone}${selected ? " is-selected" : ""}`}>
      <Handle type="target" position={Position.Top} />
      <span className="node-kind">{type}</span>
      <strong>{data.label}</strong>
      {label && <span className="node-label">{label}</span>}
      {(data.file || data.cwe) && (
        <span className="node-meta">
          {[data.cwe, data.file && `${data.file}${data.line ? `:${data.line}` : ""}`]
            .filter(Boolean)
            .join(" · ")}
        </span>
      )}
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

const nodeTypes = {
  endpoint: CorrelationNode,
  controller: CorrelationNode,
  sink: CorrelationNode,
  evidence: CorrelationNode,
  suppressed: CorrelationNode,
};

function flowNode(node: GraphNode): FlowNode {
  return {
    id: node.id,
    type: node.type,
    position: node.position,
    data: node.data,
    width: node.type === "evidence" ? 220 : 240,
    height: node.type === "evidence" ? 86 : 104,
  };
}

interface CorrelationGraphProps {
  graph: GraphResponse;
  onSelectFinding: (findingId: string | null) => void;
}

export function CorrelationGraph({
  graph,
  onSelectFinding,
}: CorrelationGraphProps) {
  const [nodes, setNodes] = useState<FlowNode[]>([]);
  const edges = useMemo<Edge[]>(
    () =>
      graph.edges.map((edge) => ({
        id: edge.id,
        source: edge.source,
        target: edge.target,
        animated: edge.animated,
        markerEnd: { type: MarkerType.ArrowClosed, color: "#56647b" },
        style: {
          stroke: edge.animated ? "#ef4444" : "#56647b",
          strokeWidth: edge.animated ? 2 : 1.4,
        },
      })),
    [graph.edges],
  );

  useEffect(() => {
    let cancelled = false;
    const inputNodes = graph.nodes.map(flowNode);
    setNodes([]);
    if (inputNodes.length === 0) {
      return () => {
        cancelled = true;
      };
    }

    void elk
      .layout({
        id: "correlation-graph",
        layoutOptions: {
          "elk.algorithm": "layered",
          "elk.direction": "DOWN",
          "elk.spacing.nodeNode": "36",
          "elk.layered.spacing.nodeNodeBetweenLayers": "72",
          "elk.edgeRouting": "ORTHOGONAL",
        },
        children: inputNodes.map((node) => ({
          id: node.id,
          width: node.width,
          height: node.height,
        })),
        edges: graph.edges.map((edge) => ({
          id: edge.id,
          sources: [edge.source],
          targets: [edge.target],
        })),
      })
      .then((layout) => {
        if (cancelled) return;
        const positions = new Map(
          layout.children?.map((node) => [
            node.id,
            { x: node.x ?? 0, y: node.y ?? 0 },
          ]),
        );
        setNodes(
          inputNodes.map((node) => ({
            ...node,
            position: positions.get(node.id) ?? { x: 0, y: 0 },
          })),
        );
      })
      .catch((error: unknown) => {
        console.error("ELK graph layout failed", error);
        if (!cancelled) setNodes(inputNodes);
      });

    return () => {
      cancelled = true;
    };
  }, [graph.edges, graph.nodes]);

  return (
    <div className="graph-canvas">
      {graph.nodes.length === 0 ? (
        <div className="empty-graph">
          <div className="empty-icon">◇</div>
          <h2>No correlation paths yet</h2>
          <p>
            This target has no parsed routes or findings. Run the target scan to
            populate its graph.
          </p>
        </div>
      ) : (
        <ReactFlow
          key={`${graph.target_id}:${nodes.length > 0 ? "ready" : "layout"}`}
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.15}
          maxZoom={1.6}
          onNodeClick={(_, node) =>
            onSelectFinding(node.data.finding_id ?? null)
          }
          onPaneClick={() => onSelectFinding(null)}
        >
          <Background color="#273144" gap={24} size={1} />
          <MiniMap
            pannable
            zoomable
            nodeColor={(node) => {
              const label = (node.data as GraphNodeData).finding_label;
              if (node.type === "suppressed") return "#536174";
              if (label === "Confirmed") return "#ef4444";
              if (label === "Code only") return "#eab308";
              if (label === "Runtime only") return "#f97316";
              return "#687993";
            }}
          />
          <Controls />
        </ReactFlow>
      )}
      <div className="graph-legend">
        <span><i className="legend-dot confirmed" />Confirmed</span>
        <span><i className="legend-dot code" />Code only</span>
        <span><i className="legend-dot runtime" />Runtime only</span>
        <span><i className="legend-dot suppressed" />Suppressed</span>
      </div>
    </div>
  );
}
