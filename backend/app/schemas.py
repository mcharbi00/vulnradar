from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import ScanStatus, Severity


# --- Auth ---

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


# --- Findings ---

class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    category: str
    severity: Severity
    title: str
    description: str
    evidence: str | None = None
    recommendation: str | None = None


# --- Scans ---

class ScanCreate(BaseModel):
    target: str = Field(
        description="Hôte ou URL à scanner (doit être dans la liste blanche autorisée)"
    )


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: ScanStatus
    progress: int
    score: float | None
    started_at: datetime
    finished_at: datetime | None


class ScanDetailOut(ScanOut):
    findings: list[FindingOut] = []
    error: str | None = None
