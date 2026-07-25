import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


# ── ID generation ──────────────────────────────────────────────────────────

def _node_id(file_path: str, func_name: str, node_type: str, sig: str) -> str:
    h = hashlib.md5(f"{file_path}::{func_name}::{sig}".encode()).hexdigest()[:7]
    return f"{node_type}_{h}"


_ID_PREFIX = {
    "IRFunction": "FUNC",
    "IRCall": "CALL",
    "IRVar": "VAR",
    "IRAccess": "ACCESS",
    "IRBranch": "BRANCH",
    "IRLiteral": "LIT",
    "IRAssign": "ASSIGN",
    "IRReturn": "RET",
    "IRCallExpr": "CALLE",
}


# ── Expressions (value-producing nodes) ────────────────────────────────────

@dataclass
class IRExpr:
    """Abstract base — type discriminator for serialization."""
    def to_dict(self) -> dict:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict) -> "IRExpr":
        mapping = {
            "IRVar": IRVar.from_dict,
            "IRAccess": IRAccess.from_dict,
            "IRLiteral": IRLiteral.from_dict,
            "IRCallExpr": IRCallExpr.from_dict,
        }
        fn = mapping.get(data.get("type", ""))
        if fn:
            return fn(data)
        raise ValueError(f"Unknown IRExpr type: {data.get('type')}")


@dataclass
class IRVar(IRExpr):
    name: str
    id: str = ""
    type: str = "IRVar"

    def __post_init__(self):
        if not self.id:
            self.id = _node_id("", "", _ID_PREFIX["IRVar"], self.name)

    def to_dict(self) -> dict:
        return {"type": self.type, "id": self.id, "name": self.name}

    @classmethod
    def from_dict(cls, data: dict) -> "IRVar":
        return cls(name=data["name"], id=data["id"])


@dataclass
class IRLiteral(IRExpr):
    value: str | int | bool | None
    value_type: str
    id: str = ""
    type: str = "IRLiteral"

    def __post_init__(self):
        if not self.id:
            self.id = _node_id("", "", _ID_PREFIX["IRLiteral"], str(self.value))

    def to_dict(self) -> dict:
        return {"type": self.type, "id": self.id, "value": self.value, "value_type": self.value_type}

    @classmethod
    def from_dict(cls, data: dict) -> "IRLiteral":
        return cls(value=data["value"], value_type=data["value_type"], id=data["id"])


@dataclass
class IRAccess(IRExpr):
    root: IRExpr
    path: list[str | IRExpr]
    id: str = ""
    type: str = "IRAccess"

    def __post_init__(self):
        if not self.id:
            path_str = ".".join(
                p if isinstance(p, str) else f"[{p.name if isinstance(p, IRVar) else str(p)}]"
                for p in self.path
            )
            self.id = _node_id("", "", _ID_PREFIX["IRAccess"], path_str)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "id": self.id,
            "root": self.root.to_dict(),
            "path": [p if isinstance(p, str) else p.to_dict() for p in self.path],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IRAccess":
        root = IRExpr.from_dict(data["root"])
        path = [
            p if isinstance(p, str) else IRExpr.from_dict(p)
            for p in data["path"]
        ]
        return cls(root=root, path=path, id=data["id"])


@dataclass
class IRCallExpr(IRExpr):
    target: str
    args: list[IRExpr]
    receiver: Optional[IRExpr] = None
    id: str = ""
    type: str = "IRCallExpr"

    def __post_init__(self):
        if not self.id:
            self.id = _node_id("", "", _ID_PREFIX["IRCallExpr"], self.target)

    def to_dict(self) -> dict:
        d = {"type": self.type, "id": self.id, "target": self.target, "args": [a.to_dict() for a in self.args]}
        if self.receiver:
            d["receiver"] = self.receiver.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "IRCallExpr":
        args = [IRExpr.from_dict(a) for a in data["args"]]
        receiver = IRExpr.from_dict(data["receiver"]) if data.get("receiver") else None
        return cls(target=data["target"], args=args, receiver=receiver, id=data["id"])


# ── Statements ─────────────────────────────────────────────────────────────

@dataclass
class IRStmt:
    """Abstract base."""
    def to_dict(self) -> dict:
        raise NotImplementedError

    @classmethod
    def from_dict(cls, data: dict) -> "IRStmt":
        mapping = {
            "IRCall": IRCall.from_dict,
            "IRAssign": IRAssign.from_dict,
            "IRBranch": IRBranch.from_dict,
            "IRReturn": IRReturn.from_dict,
        }
        fn = mapping.get(data.get("type", ""))
        if fn:
            return fn(data)
        raise ValueError(f"Unknown IRStmt type: {data.get('type')}")


@dataclass
class IRCall(IRStmt):
    target: str
    args: list[IRExpr]
    receiver: Optional[IRExpr] = None
    result_var: Optional[str] = None
    line: int = 0
    id: str = ""
    type: str = "IRCall"

    def __post_init__(self):
        if not self.id:
            self.id = _node_id("", "", _ID_PREFIX["IRCall"], self.target)

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "id": self.id,
            "target": self.target,
            "args": [a.to_dict() for a in self.args],
            "line": self.line,
        }
        if self.receiver:
            d["receiver"] = self.receiver.to_dict()
        if self.result_var:
            d["result_var"] = self.result_var
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "IRCall":
        args = [IRExpr.from_dict(a) for a in data["args"]]
        receiver = IRExpr.from_dict(data["receiver"]) if data.get("receiver") else None
        return cls(
            target=data["target"],
            args=args,
            receiver=receiver,
            result_var=data.get("result_var"),
            line=data.get("line", 0),
            id=data["id"],
        )


@dataclass
class IRAssign(IRStmt):
    target: str
    value: IRExpr
    line: int = 0
    id: str = ""
    type: str = "IRAssign"

    def __post_init__(self):
        if not self.id:
            self.id = _node_id("", "", _ID_PREFIX["IRAssign"], f"{self.target}=")

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "id": self.id,
            "target": self.target,
            "value": self.value.to_dict(),
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IRAssign":
        return cls(
            target=data["target"],
            value=IRExpr.from_dict(data["value"]),
            line=data.get("line", 0),
            id=data["id"],
        )


@dataclass
class IRBranch(IRStmt):
    condition: IRExpr
    true_body: list[IRStmt]
    false_body: list[IRStmt]
    line: int = 0
    id: str = ""
    type: str = "IRBranch"

    def __post_init__(self):
        if not self.id:
            c_text = self.condition.to_dict().get("target", str(self.condition)) if self.condition is not None else "none"
            self.id = _node_id("", "", _ID_PREFIX["IRBranch"], c_text)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "id": self.id,
            "condition": self.condition.to_dict() if self.condition is not None else None,
            "true_body": [s.to_dict() for s in self.true_body],
            "false_body": [s.to_dict() for s in self.false_body],
            "line": self.line,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IRBranch":
        return cls(
            condition=IRExpr.from_dict(data["condition"]) if data.get("condition") else None,
            true_body=[IRStmt.from_dict(s) for s in data["true_body"]],
            false_body=[IRStmt.from_dict(s) for s in data["false_body"]],
            line=data.get("line", 0),
            id=data["id"],
        )


@dataclass
class IRReturn(IRStmt):
    value: Optional[IRExpr] = None
    line: int = 0
    id: str = ""
    type: str = "IRReturn"

    def __post_init__(self):
        if not self.id:
            self.id = _node_id("", "", _ID_PREFIX["IRReturn"], "")

    def to_dict(self) -> dict:
        d: dict = {"type": self.type, "id": self.id, "line": self.line}
        if self.value:
            d["value"] = self.value.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "IRReturn":
        value = IRExpr.from_dict(data["value"]) if data.get("value") else None
        return cls(value=value, line=data.get("line", 0), id=data["id"])


# ── Function ───────────────────────────────────────────────────────────────

@dataclass
class IRFunction:
    name: str
    params: list[str]
    body: list[IRStmt]
    file_path: str
    line: int = 0
    is_async: bool = False
    id: str = ""
    type: str = "IRFunction"

    def __post_init__(self):
        if not self.id:
            sig = f"{self.name}({','.join(self.params)})"
            self.id = _node_id(self.file_path, "global", _ID_PREFIX["IRFunction"], sig)

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "id": self.id,
            "name": self.name,
            "params": self.params,
            "body": [s.to_dict() for s in self.body],
            "file_path": self.file_path,
            "line": self.line,
            "is_async": self.is_async,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IRFunction":
        return cls(
            name=data["name"],
            params=data["params"],
            body=[IRStmt.from_dict(s) for s in data["body"]],
            file_path=data["file_path"],
            line=data.get("line", 0),
            is_async=data.get("is_async", False),
            id=data["id"],
        )


# ── Call Resolution (parallel layer) ──────────────────────────────────────

@dataclass
class CallResolution:
    call_id: str
    resolved_fn_id: Optional[str] = None
    candidates: list[str] = field(default_factory=list)
    confidence: float = 1.0
    receiver_type: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"call_id": self.call_id}
        if self.resolved_fn_id:
            d["resolved_fn_id"] = self.resolved_fn_id
        if self.candidates:
            d["candidates"] = self.candidates
        if self.confidence < 1.0:
            d["confidence"] = self.confidence
        if self.receiver_type:
            d["receiver_type"] = self.receiver_type
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "CallResolution":
        return cls(
            call_id=data["call_id"],
            resolved_fn_id=data.get("resolved_fn_id"),
            candidates=data.get("candidates", []),
            confidence=data.get("confidence", 1.0),
            receiver_type=data.get("receiver_type"),
        )


# ── Parallel layers ────────────────────────────────────────────────────────

@dataclass
class Edge:
    source_id: str
    target_id: str
    transform: Optional[str] = None
    conditions: list[int] = field(default_factory=list)
    confidence: float = 1.0

    def to_dict(self) -> dict:
        d = {"source_id": self.source_id, "target_id": self.target_id}
        if self.transform:
            d["transform"] = self.transform
        if self.conditions:
            d["conditions"] = self.conditions
        if self.confidence < 1.0:
            d["confidence"] = self.confidence
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Edge":
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            transform=data.get("transform"),
            conditions=data.get("conditions", []),
            confidence=data.get("confidence", 1.0),
        )


@dataclass
class Tag:
    kind: str
    node_id: str

    def to_dict(self) -> dict:
        return {"kind": self.kind, "node_id": self.node_id}

    @classmethod
    def from_dict(cls, data: dict) -> "Tag":
        return cls(kind=data["kind"], node_id=data["node_id"])


# ── Module (one per file) ──────────────────────────────────────────────────

@dataclass
class IRModule:
    file_path: str
    language: str
    functions: list[IRFunction]
    provenance_edges: list[Edge] = field(default_factory=list)
    semantic_tags: list[Tag] = field(default_factory=list)
    call_resolutions: list[CallResolution] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "language": self.language,
            "functions": [f.to_dict() for f in self.functions],
            "provenance_edges": [e.to_dict() for e in self.provenance_edges],
            "semantic_tags": [t.to_dict() for t in self.semantic_tags],
            "call_resolutions": [r.to_dict() for r in self.call_resolutions],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "IRModule":
        return cls(
            file_path=data["file_path"],
            language=data["language"],
            functions=[IRFunction.from_dict(f) for f in data["functions"]],
            provenance_edges=[Edge.from_dict(e) for e in data.get("provenance_edges", [])],
            semantic_tags=[Tag.from_dict(t) for t in data.get("semantic_tags", [])],
            call_resolutions=[CallResolution.from_dict(r) for r in data.get("call_resolutions", [])],
        )

    @classmethod
    def from_json(cls, text: str) -> "IRModule":
        return cls.from_dict(json.loads(text))

    # ── convenience helpers ────────────────────────────────────────────────

    def add_edge(self, source_id: str, target_id: str, transform: str | None = None, conditions: list[int] | None = None, confidence: float = 1.0):
        self.provenance_edges.append(Edge(
            source_id=source_id,
            target_id=target_id,
            transform=transform,
            conditions=conditions or [],
            confidence=confidence,
        ))

    def add_resolution(self, call_id: str, resolved_fn_id: str | None = None, candidates: list[str] | None = None, confidence: float = 1.0, receiver_type: str | None = None):
        self.call_resolutions.append(CallResolution(
            call_id=call_id,
            resolved_fn_id=resolved_fn_id,
            candidates=candidates or [],
            confidence=confidence,
            receiver_type=receiver_type,
        ))

    def add_tag(self, kind: str, node_id: str):
        self.semantic_tags.append(Tag(kind=kind, node_id=node_id))

    def get_function(self, func_id: str) -> Optional[IRFunction]:
        for fn in self.functions:
            if fn.id == func_id:
                return fn
        return None

    def collect_nodes(self) -> list[dict]:
        """Yield all IR nodes across the module (for debugging)."""
        nodes = []
        for fn in self.functions:
            nodes.append({"id": fn.id, "type": "IRFunction", "name": fn.name})
            self._collect_stmt_nodes(fn.body, nodes)
        return nodes

    @staticmethod
    def _collect_stmt_nodes(stmts: list[IRStmt], acc: list[dict]):
        for s in stmts:
            if isinstance(s, IRCall):
                acc.append({"id": s.id, "type": "IRCall", "target": s.target, "line": s.line})
            elif isinstance(s, IRAssign):
                acc.append({"id": s.id, "type": "IRAssign", "target": s.target, "line": s.line})
            elif isinstance(s, IRBranch):
                acc.append({"id": s.id, "type": "IRBranch", "line": s.line})
                IRModule._collect_stmt_nodes(s.true_body, acc)
                IRModule._collect_stmt_nodes(s.false_body, acc)
            elif isinstance(s, IRReturn):
                acc.append({"id": s.id, "type": "IRReturn", "line": s.line})
