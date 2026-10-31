from __future__ import annotations

import hashlib
import re
import threading
from pathlib import Path
from typing import Any

from ..ast_mapper.route_schema import RouteNode
from ..ingestion.schema import UnifiedFinding
from .assessment_schema import CodeContextAssessment

MODEL_ID = "microsoft/graphcodebert-base"
MODEL_REVISION = "9b8660679da59fe3e7423b03efa48d41944eec42"
TASK_HEAD_VERSION = "masked-mean-cosine-v1"
PREPROCESSOR_VERSION = "lexical-dataflow-graph-mask-v1"
QUERY_SEQUENCE_LENGTH = 128
CODE_SEQUENCE_LENGTH = 256
DATAFLOW_NODE_LENGTH = 64
MAX_CODE_CHARS = 12_000
_IDENTIFIER = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
_KEYWORDS = {
    "and", "as", "async", "await", "break", "case", "catch", "class", "const",
    "continue", "def", "del", "elif", "else", "except", "false", "finally", "for",
    "from", "function", "if", "import", "in", "is", "lambda", "let", "new", "null",
    "or", "pass", "raise", "return", "self", "static", "switch", "this", "throw",
    "true", "try", "var", "while", "with", "yield",
}

_MODEL_LOCK = threading.RLock()
_MODEL: tuple[Any, Any, Any] | None = None
_SCORE_CACHE: dict[str, float] = {}


def route_candidate_id(route: RouteNode) -> str:
    identity = (
        route.target_id,
        route.raw_url,
        route.normalized_url,
        "|".join(sorted(route.methods)),
        route.handler,
        route.scopes[0].file if route.scopes else "",
    )
    return hashlib.sha256("|".join(identity).encode("utf-8")).hexdigest()[:16]


def _load_model() -> tuple[Any, Any, Any]:
    """Load the pinned public encoder once; never substitute a synthetic score."""
    global _MODEL
    with _MODEL_LOCK:
        if _MODEL is None:
            try:
                import torch
                from transformers import AutoModel, AutoTokenizer
            except ImportError as exc:
                raise RuntimeError(
                    "GraphCodeBERT requires the pinned torch and transformers dependencies"
                ) from exc

            tokenizer = AutoTokenizer.from_pretrained(
                MODEL_ID,
                revision=MODEL_REVISION,
                use_fast=True,
            )
            model = AutoModel.from_pretrained(
                MODEL_ID,
                revision=MODEL_REVISION,
                use_safetensors=True,
                add_pooling_layer=False,
            )
            model.to("cpu")
            model.eval()
            _MODEL = (torch, tokenizer, model)
        return _MODEL


def _dataflow_code_inputs(code: str, tokenizer: Any, torch: Any) -> dict[str, Any]:
    """Build GraphCodeBERT-style token, position, and graph-guided attention inputs.

    Identifier def/use links are a bounded lexical approximation, not a taint graph.
    The model's correlation authority remains the deterministic route mapper.
    """
    tokenized = tokenizer(
        code,
        add_special_tokens=False,
        truncation=True,
        max_length=CODE_SEQUENCE_LENGTH - 2,
        return_offsets_mapping=True,
    )
    code_ids = list(tokenized["input_ids"])
    offsets = list(tokenized["offset_mapping"])
    occurrences: dict[str, list[tuple[int, int]]] = {}
    for match in _IDENTIFIER.finditer(code):
        name = match.group(0)
        if name.lower() in _KEYWORDS:
            continue
        token_span = [
            index
            for index, (start, end) in enumerate(offsets)
            if end > match.start() and start < match.end()
        ]
        if token_span:
            occurrences.setdefault(name, []).append((token_span[0], token_span[-1] + 1))

    nodes: list[tuple[int, int, int | None]] = []
    previous_node: dict[str, int] = {}
    for name, spans in occurrences.items():
        if len(spans) < 2:
            continue
        for span in spans:
            if len(nodes) >= DATAFLOW_NODE_LENGTH:
                break
            current = len(nodes)
            nodes.append((span[0], span[1], previous_node.get(name)))
            previous_node[name] = current

    input_ids = [tokenizer.cls_token_id, *code_ids, tokenizer.sep_token_id]
    code_token_count = len(input_ids)
    max_nodes = min(DATAFLOW_NODE_LENGTH, len(nodes))
    input_ids.extend([tokenizer.unk_token_id] * max_nodes)
    sequence_length = CODE_SEQUENCE_LENGTH + DATAFLOW_NODE_LENGTH
    pad_count = sequence_length - len(input_ids)
    position_idx = [index + tokenizer.pad_token_id + 1 for index in range(code_token_count)]
    position_idx.extend([0] * max_nodes)
    input_ids.extend([tokenizer.pad_token_id] * pad_count)
    position_idx.extend([tokenizer.pad_token_id] * pad_count)

    node_index = code_token_count
    max_length = code_token_count + max_nodes
    attention = torch.zeros((sequence_length, sequence_length), dtype=torch.bool)
    attention[:node_index, :node_index] = True
    for index, token_id in enumerate(input_ids[:node_index]):
        if token_id in {tokenizer.cls_token_id, tokenizer.sep_token_id}:
            attention[index, :max_length] = True
    for index, (start, end, predecessor) in enumerate(nodes[:max_nodes]):
        graph_node = node_index + index
        token_start, token_end = start + 1, end + 1
        attention[graph_node, token_start:token_end] = True
        attention[token_start:token_end, graph_node] = True
        if predecessor is not None:
            attention[graph_node, node_index + predecessor] = True

    return {
        "input_ids": torch.tensor([input_ids], dtype=torch.long),
        "position_idx": torch.tensor([position_idx], dtype=torch.long),
        "attention_mask": attention.unsqueeze(0),
    }


def _graph_code_embedding(code: str, tokenizer: Any, model: Any, torch: Any) -> Any:
    features = _dataflow_code_inputs(code, tokenizer, torch)
    code_ids = features["input_ids"]
    position_idx = features["position_idx"]
    attention = features["attention_mask"]
    nodes_mask = position_idx.eq(0)
    token_mask = position_idx.ge(2)
    embeddings = model.embeddings.word_embeddings(code_ids)
    node_to_token = (
        nodes_mask[:, :, None] & token_mask[:, None, :] & attention
    ).to(embeddings.dtype)
    node_to_token = node_to_token / (node_to_token.sum(-1, keepdim=True) + 1e-10)
    node_embeddings = torch.einsum("abc,acd->abd", node_to_token, embeddings)
    embeddings = (
        embeddings * (~nodes_mask)[:, :, None]
        + node_embeddings * nodes_mask[:, :, None]
    )
    outputs = model(
        inputs_embeds=embeddings,
        attention_mask=attention,
        position_ids=position_idx,
    )
    return _masked_mean(outputs.last_hidden_state, token_mask, torch)


def _masked_mean(hidden_states: Any, mask: Any, torch: Any) -> Any:
    weights = mask.unsqueeze(-1).to(hidden_states.dtype)
    summed = torch.sum(hidden_states * weights, dim=1)
    denominator = torch.sum(weights, dim=1).clamp_min(1e-9)
    return summed / denominator


def _read_route_context(
    route: RouteNode,
    source_root: Path | None,
) -> tuple[str, list[dict[str, Any]]]:
    refs: list[dict[str, Any]] = []
    chunks: list[str] = []
    root = source_root.resolve() if source_root is not None else None
    remaining = MAX_CODE_CHARS

    if root is not None:
        for scope in route.scopes:
            candidate = (root / scope.file).resolve()
            if not candidate.is_relative_to(root) or not candidate.is_file():
                continue
            try:
                lines = candidate.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                continue
            snippet = "\n".join(lines[scope.start_line - 1 : scope.end_line])
            if not snippet:
                continue
            snippet = snippet[:remaining]
            chunks.append(
                f"# {scope.file}:{scope.start_line}-{scope.end_line} {scope.function}\n{snippet}"
            )
            remaining -= len(snippet)
            refs.append(
                {
                    "file": scope.file,
                    "start_line": scope.start_line,
                    "end_line": scope.end_line,
                    "function": scope.function,
                }
            )
            if remaining <= 0:
                break

    return "\n\n".join(chunks), refs


class GraphCodeBERTShadowRanker:
    """Advisory code-search ranker backed by the pinned GraphCodeBERT encoder."""

    def __init__(
        self,
        *,
        mode: str = "SHADOW",
        source_revision: str | None = None,
        enabled: bool = True,
        source_root: Path | None = None,
    ) -> None:
        self.mode = str(mode).upper()
        self.enabled = enabled
        self.source_revision = source_revision
        self.source_root = source_root

    @property
    def is_available(self) -> bool:
        """Report whether the inference dependencies are installed locally."""
        try:
            import torch  # noqa: F401
            from transformers import AutoModel, AutoTokenizer  # noqa: F401
        except (ImportError, OSError, RuntimeError):
            return False
        return True

    def _query(self, finding: UnifiedFinding, route: RouteNode) -> str:
        parameters = ", ".join(
            f"{parameter.source} parameter {parameter.name}"
            for parameter in route.input_parameters
        ) or "no statically identified request parameter"
        return (
            f"Find code relevant to {finding.cwe_id} {finding.sink_type or finding.rule_id or 'security vulnerability'}. "
            f"This code handles {', '.join(sorted(route.methods))} {route.normalized_url} "
            f"in {route.handler} and reads {parameters}. "
            f"Finding location: {finding.file or 'unknown'} line {finding.line or 'unknown'}."
        )

    def build_assessment(
        self,
        scan_id: str,
        finding: UnifiedFinding,
        route: RouteNode,
    ) -> CodeContextAssessment:
        route_id = route_candidate_id(route)
        assessment_id = f"gcb-{hashlib.sha256(f'{scan_id}:{finding.id}:{route_id}'.encode()).hexdigest()[:12]}"
        code, refs = _read_route_context(route, self.source_root)
        if not self.enabled:
            return self._unavailable(
                assessment_id, scan_id, finding, route_id, refs,
                "MODEL_DISABLED", "SKIPPED", self.mode, self.source_revision,
            )
        if not self.is_available:
            return self._unavailable(
                assessment_id, scan_id, finding, route_id, refs,
                "TRANSFORMERS_UNAVAILABLE", "SKIPPED", self.mode, self.source_revision,
            )
        if not code:
            return self._unavailable(
                assessment_id, scan_id, finding, route_id, refs,
                "SOURCE_CONTEXT_UNAVAILABLE", "SKIPPED", self.mode, self.source_revision,
            )

        try:
            query = self._query(finding, route)
            score_key = hashlib.sha256(f"{MODEL_REVISION}\0{query}\0{code}".encode()).hexdigest()
            with _MODEL_LOCK:
                score = _SCORE_CACHE.get(score_key)
                if score is None:
                    torch, tokenizer, model = _load_model()
                    with torch.inference_mode():
                        query_inputs = tokenizer(
                            query,
                            padding="max_length",
                            truncation=True,
                            max_length=QUERY_SEQUENCE_LENGTH,
                            return_tensors="pt",
                        )
                        query_outputs = model(
                            input_ids=query_inputs["input_ids"],
                            attention_mask=query_inputs["attention_mask"],
                        )
                        query_vector = _masked_mean(
                            query_outputs.last_hidden_state,
                            query_inputs["attention_mask"].bool(),
                            torch,
                        )
                        code_vector = _graph_code_embedding(code, tokenizer, model, torch)
                        vectors = torch.nn.functional.normalize(
                            torch.cat((query_vector, code_vector), dim=0), p=2, dim=1
                        )
                        cosine = torch.sum(vectors[0] * vectors[1]).item()
                    score = round(max(0.0, min(1.0, (cosine + 1.0) / 2.0)), 6)
                    if len(_SCORE_CACHE) >= 2048:
                        _SCORE_CACHE.clear()
                    _SCORE_CACHE[score_key] = score
        except Exception as exc:
            # A failed model load/inference is visible as an error, never a fake score.
            return self._unavailable(
                assessment_id,
                scan_id,
                finding,
                route_id,
                refs,
                f"MODEL_INFERENCE_FAILED:{type(exc).__name__}",
                "ERROR",
                self.mode,
                self.source_revision,
            )

        return CodeContextAssessment(
            assessment_id=assessment_id,
            scan_id=scan_id,
            target_id=finding.target_id,
            finding_id=finding.id,
            candidate_route_id=route_id,
            model_id=MODEL_ID,
            model_revision=MODEL_REVISION,
            task_head_version=TASK_HEAD_VERSION,
            preprocessor_version=PREPROCESSOR_VERSION,
            source_revision=self.source_revision,
            status="AVAILABLE",
            relevance_score=score,
            score_calibration="UN_CALIBRATED",
            evidence_refs=refs,
            limitations=[
                "ADVISORY_ONLY",
                "PRETRAINED_ENCODER_WITHOUT_TASK_FINETUNING",
                "LEXICAL_DATAFLOW_LINKS_ARE_APPROXIMATE",
                "COSINE_SCORE_IS_NOT_A_PROBABILITY",
            ],
            mode=self.mode,
        )

    @staticmethod
    def _unavailable(
        assessment_id: str,
        scan_id: str,
        finding: UnifiedFinding,
        route_id: str,
        refs: list[dict[str, Any]],
        reason: str,
        status: str,
        mode: str,
        source_revision: str | None,
    ) -> CodeContextAssessment:
        return CodeContextAssessment(
            assessment_id=assessment_id,
            scan_id=scan_id,
            target_id=finding.target_id,
            finding_id=finding.id,
            candidate_route_id=route_id,
            model_id=MODEL_ID,
            model_revision=MODEL_REVISION,
            task_head_version=TASK_HEAD_VERSION,
            preprocessor_version=PREPROCESSOR_VERSION,
            source_revision=source_revision,
            status=status,
            score_calibration="UN_CALIBRATED",
            evidence_refs=refs,
            limitations=[reason],
            mode=mode,
        )

    def assess_candidates(
        self,
        scan_id: str,
        target_id: str,
        findings: list[UnifiedFinding],
        routes: list[RouteNode],
    ) -> list[CodeContextAssessment]:
        assessments: list[CodeContextAssessment] = []
        if not findings or not routes:
            return assessments

        for finding in findings:
            if finding.target_id != target_id or finding.source != "sast":
                continue
            candidates = [
                route
                for route in routes
                if route.target_id == target_id
                and route.resolved
                and route.contains_location(finding.file, finding.line)
                and (route.input_parameters or route.scopes)
            ]
            # Score deterministic source-mapped candidates; only ties affect scheduling.
            if not candidates:
                continue
            for route in candidates:
                assessments.append(self.build_assessment(scan_id, finding, route))
        return assessments
