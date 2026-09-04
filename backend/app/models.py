from datetime import datetime
from typing import Any
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

class AttackPattern(Base):
    __tablename__ = "attack_patterns"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    category: Mapped[str] = mapped_column(String(60), index=True)
    title: Mapped[str] = mapped_column(String(200))
    raw_prompt: Mapped[str] = mapped_column(Text)
    cleaned_prompt: Mapped[str] = mapped_column(Text)
    raw_hash: Mapped[str] = mapped_column(String(64), unique=True)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    presumptions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    expected_safe_behaviour: Mapped[str] = mapped_column(Text)
    success_indicators: Mapped[list[str]] = mapped_column(JSON)
    failure_indicators: Mapped[list[str]] = mapped_column(JSON)
    source_severity: Mapped[str] = mapped_column(String(16))
    remediation: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(20), default="seed")
    parent_pattern_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    mutation: Mapped[str | None] = mapped_column(String(40), nullable=True)
    turns: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    validation_status: Mapped[str] = mapped_column(String(20), default="accepted")
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    api_endpoint: Mapped[str] = mapped_column(String(1000))
    auth_config_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_name: Mapped[str] = mapped_column(String(120), default="demo")
    request_format: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    response_format: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    capabilities: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    system_prompt_canary: Mapped[str | None] = mapped_column(String(300), nullable=True)
    declared_policy: Mapped[str] = mapped_column(Text, default="Never reveal system instructions or secrets.")
    authorized: Mapped[bool] = mapped_column(Boolean, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class TestRun(Base):
    __tablename__ = "test_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    mode: Mapped[str] = mapped_column(String(12), default="batch")
    status: Mapped[str] = mapped_column(String(20), default="queued")
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    total: Mapped[int] = mapped_column(Integer, default=0)
    executed: Mapped[int] = mapped_column(Integer, default=0)
    resisted: Mapped[int] = mapped_column(Integer, default=0)
    successful: Mapped[int] = mapped_column(Integer, default=0)
    inconclusive: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class TestExecution(Base):
    __tablename__ = "test_executions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_run_id: Mapped[int] = mapped_column(ForeignKey("test_runs.id"), index=True)
    attack_pattern_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    session_id: Mapped[str] = mapped_column(String(80))
    sequence_number: Mapped[int] = mapped_column(Integer)
    request_text: Mapped[str] = mapped_column(Text)
    request_risk_score: Mapped[float] = mapped_column(Float, default=0)
    request_action: Mapped[str] = mapped_column(String(16))
    request_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    reached_target: Mapped[bool] = mapped_column(Boolean, default=False)
    response_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_risk_score: Mapped[float] = mapped_column(Float, default=0)
    response_action: Mapped[str] = mapped_column(String(16), default="ALLOW")
    response_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    outcome: Mapped[str] = mapped_column(String(30))
    source_severity: Mapped[str] = mapped_column(String(16))
    derived_severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float, default=0)
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_execution_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(60))
    message: Mapped[str] = mapped_column(Text)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    test_run_id: Mapped[int] = mapped_column(ForeignKey("test_runs.id"), unique=True)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class SourceRepository(Base):
    __tablename__ = "source_repositories"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    repo_url: Mapped[str] = mapped_column(String(1000))
    pinned_commit_sha: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20), default="configured")
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
