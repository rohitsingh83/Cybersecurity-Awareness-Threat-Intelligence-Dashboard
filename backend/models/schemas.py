"""Validated request models for API inputs; unknown fields are rejected."""
from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    threat_id: Optional[str] = Field(default=None, max_length=64)
    threat_name: str = Field(min_length=3, max_length=160)
    threat_category: str = Field(min_length=3, max_length=40)
    indicator_type: str = Field(min_length=2, max_length=40)
    indicator_value: str = Field(min_length=1, max_length=2048)
    source_name: str = Field(default="Internal SOC", max_length=100)
    source_reliability: str = Field(default="C", max_length=10)
    confidence_score: int = Field(default=50, ge=0, le=100)
    risk_score: Optional[int] = Field(default=None, ge=0, le=100)
    status: str = Field(default="NEW", max_length=32)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: str = Field(default="Synthetic observation awaiting analyst review.", max_length=1200)
    campaign_id: Optional[str] = Field(default=None, max_length=100)
    observed_count: int = Field(default=1, ge=1, le=100000)


class StatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(min_length=2, max_length=32)


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=3, max_length=1000)
    author_label: str = Field(default="LOCAL ANALYST", max_length=80)


class QuizSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answers: dict[str, int] = Field(default_factory=dict)
    anonymous_user_id: Optional[str] = Field(default=None, max_length=64)
