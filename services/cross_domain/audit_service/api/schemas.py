"""audit-service 的 HTTP 契约。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class RecordIn(BaseModel):
    kind: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    payload: dict = Field(default_factory=dict)


class RecordOut(BaseModel):
    entryId: str
    seq: int
    hash: str


class AttestIn(BaseModel):
    did: str = Field(min_length=1)
    phc: dict
    parentDid: str = ""


class VerifyOut(BaseModel):
    ok: bool
    length: int
    brokenAt: int = -1
    reason: str = ""


class ExportIn(BaseModel):
    caseRef: str = ""
    subjects: list[str] = Field(default_factory=list)
    includeAll: bool = False


class EntryOut(BaseModel):
    seq: int
    entryId: str
    at: str
    kind: str
    subject: str
    payload: dict = Field(default_factory=dict)
    prevHash: str = ""
    hash: str = ""


class BundleOut(BaseModel):
    caseRef: str
    exportedAt: str
    entries: list[dict]
    verification: dict | None = None
    bundleDigest: str
    note: str = ""


class ErrorOut(BaseModel):
    code: int
    message: str
    detail: str | None = None


__all__ = ["RecordIn", "RecordOut", "AttestIn", "VerifyOut", "ExportIn",
           "EntryOut", "BundleOut", "ErrorOut"]
