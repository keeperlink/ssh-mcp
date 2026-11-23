"""Versioned live SSH/job request API contracts.

Validation and schemas are used by the live authenticated MCP dispatcher.
Directly parsing a request alone does not execute a command.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from . import config

CONTRACT_VERSION = "2.0"
ArgItem = Annotated[str, Field(min_length=1, max_length=config.SSH_MAX_ARGUMENT_BYTES, strict=True)]
JobStatus = Literal["awaiting_approval", "queued", "running", "succeeded", "failed", "cancelled", "timed_out", "transport_error", "output_limit", "interrupted", "denied"]


class StrictRequest(BaseModel):
    """All request schemas forbid extra parameters and implicit coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ListServersRequest(StrictRequest):
    """Empty request; server discovery must use an approved server registry."""


class ExecuteCommandRequest(StrictRequest):
    server: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    privileged: bool = Field(default=False, strict=True)
    argv: list[ArgItem] = Field(min_length=1, max_length=config.SSH_MAX_ARGUMENTS)
    timeout_seconds: int = Field(default=config.SSH_DEFAULT_TIMEOUT_SECONDS, ge=1, le=config.SSH_MAX_TIMEOUT_SECONDS, strict=True)
    reason: str = Field(min_length=1, max_length=200)
    story_id: str | None = Field(default=None, min_length=1, max_length=80, pattern=r"^[^\s\x00-\x1F\x7F-\x9F]+$")
    cwd: str | None = Field(default=None, min_length=1, max_length=4096, strict=True)
    success_exit_codes: list[int] = Field(default_factory=lambda: [0], min_length=1, max_length=16)
    strict_bash: bool = Field(default=False, strict=True)

    @field_validator("cwd")
    @classmethod
    def absolute_cwd(cls, value: str | None) -> str | None:
        if value is not None and (
            not value.startswith("/") or "\x00" in value or "\n" in value or "\r" in value
        ):
            raise ValueError("cwd must be a single absolute POSIX path")
        return value

    @field_validator("success_exit_codes")
    @classmethod
    def valid_exit_codes(cls, values: list[int]) -> list[int]:
        if (
            any(type(code) is not int or code < 0 or code > 254 for code in values)
            or len(values) != len(set(values))
        ):
            raise ValueError("Success exit codes must be distinct integers from 0 to 254")
        return values

    @model_validator(mode="after")
    def recognized_bash_syntax(self) -> Self:
        if self.strict_bash and self.argv[0] in {"bash", "/bin/bash", "/usr/bin/bash"}:
            if len(self.argv) < 3 or self.argv[1] not in {"-c", "-lc"}:
                raise ValueError("strict_bash requires explicit bash -c or bash -lc with a script")
        return self

    @field_validator("argv")
    @classmethod
    def validate_argument_bytes(cls, values: list[str]) -> list[str]:
        if any(len(value.encode("utf-8")) > config.SSH_MAX_ARGUMENT_BYTES for value in values):
            raise ValueError("SSH argument exceeds configured byte limit")
        return values

    # No arbitrary shell string or executable path interpolation here.
    # The future execution layer MUST check allowlists and enforce authorization.


class BatchStepRequest(StrictRequest):
    """One bounded argv step; server, actor, cwd, strictness and reason are shared."""

    argv: list[ArgItem] = Field(min_length=1, max_length=config.SSH_MAX_ARGUMENTS)
    success_exit_codes: list[int] = Field(default_factory=lambda: [0], min_length=1, max_length=16)
    timeout_seconds: int | None = Field(default=None, ge=1, le=config.SSH_MAX_TIMEOUT_SECONDS,
                                         strict=True)

    @field_validator("success_exit_codes")
    @classmethod
    def accepted_codes(cls, codes: list[int]) -> list[int]:
        return ExecuteCommandRequest.valid_exit_codes(codes)

    @field_validator("argv")
    @classmethod
    def encoded_argument_bounds(cls, values: list[str]) -> list[str]:
        return ExecuteCommandRequest.validate_argument_bytes(values)


class ExecuteCommandsRequest(StrictRequest):
    """One non-transactional sequential batch, always on a single approved host."""

    server: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    privileged: bool = Field(default=False, strict=True)
    commands: list[BatchStepRequest] = Field(min_length=1, max_length=5)
    timeout_seconds: int = Field(default=config.SSH_DEFAULT_TIMEOUT_SECONDS, ge=1,
                                  le=min(900, config.SSH_MAX_TIMEOUT_SECONDS), strict=True)
    reason: str = Field(min_length=1, max_length=200)
    story_id: str | None = Field(default=None, min_length=1, max_length=80,
                                 pattern=r"^[^\s\x00-\x1F\x7F-\x9F]+$")
    cwd: str | None = Field(default=None, min_length=1, max_length=4096, strict=True)
    strict_bash: bool = Field(default=False, strict=True)
    stop_on_error: bool = Field(default=True, strict=True)

    @field_validator("cwd")
    @classmethod
    def validated_cwd(cls, value: str | None) -> str | None:
        return ExecuteCommandRequest.absolute_cwd(value)

    @model_validator(mode="after")
    def fully_validated(self) -> Self:
        # Preflight every step before SSH execution, using the same byte,
        # strict-Bash, argv and accepted-exit rules as a single command.
        for index, step in enumerate(self.commands):
            try:
                self.step_command(index)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"commands[{index}].argv: invalid step configuration") from exc
        if len(json.dumps(self.model_dump(exclude_none=True), ensure_ascii=False).encode("utf-8")) > 32768:
            raise ValueError("Aggregate batch arguments exceed the 32 KiB request limit")
        return self

    def step_command(self, index: int, *, timeout_seconds: int | None = None) -> ExecuteCommandRequest:
        step = self.commands[index]
        return ExecuteCommandRequest.model_validate({
            "server": self.server, "privileged": self.privileged,
            "argv": step.argv, "reason": self.reason,
            "story_id": self.story_id, "cwd": self.cwd,
            "strict_bash": self.strict_bash,
            "success_exit_codes": step.success_exit_codes,
            "timeout_seconds": timeout_seconds or step.timeout_seconds or self.timeout_seconds,
        })


class GetBatchRequest(StrictRequest):
    batch_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    cursor: int = Field(default=0, ge=0, le=4, strict=True)
    limit: int = Field(default=5, ge=1, le=5, strict=True)


class ListBatchesRequest(StrictRequest):
    limit: int = Field(default=10, ge=1, le=50, strict=True)
    cursor: int = Field(default=0, ge=0, le=1000000, strict=True)


class CancelBatchRequest(StrictRequest):
    batch_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    reason: str = Field(min_length=1, max_length=200)


class GetJobRequest(StrictRequest):
    job_id: str = Field(min_length=8, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class GetJobOutputRequest(GetJobRequest):
    cursor: int = Field(default=0, ge=0, strict=True)
    max_bytes: int = Field(default=16384, ge=1, le=65536, strict=True)


class HistoryFilters(StrictRequest):
    """Bounded, shared MCP audit filters; no caller-supplied actor."""
    host: str | None = Field(default=None, min_length=1, max_length=80)
    conversation_id: str | None = Field(default=None, min_length=1, max_length=256)
    story_id: str | None = Field(default=None, min_length=1, max_length=80)
    command: str | None = Field(default=None, min_length=1, max_length=64)
    status: JobStatus | Literal["partial", "unknown"] | None = None
    mode: Literal["sync", "async", "file", "batch"] | None = None
    record_kind: Literal["command", "file", "batch", "all"] = "command"
    time_range: Literal["1h", "8h", "24h", "7d", "30d", "all"] | None = None
    from_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    to_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")

    @model_validator(mode="after")
    def compatible_dates(self) -> Self:
        if self.time_range is not None and (self.from_date or self.to_date):
            raise ValueError("Use either time_range or explicit UTC dates")
        if self.mode in {"file", "batch"} and self.record_kind == "command":
            if "record_kind" in self.model_fields_set:
                raise ValueError("Mode conflicts with command record kind")
            self.record_kind = "file" if self.mode == "file" else "batch"
        return self

    def history_filters(self) -> dict[str, str]:
        return {
            key: str(value) for key, value in self.model_dump(
                exclude_none=True, exclude={"limit", "cursor", "group_by"}
            ).items()
        }


class ListJobsRequest(HistoryFilters):
    limit: int = Field(default=20, ge=1, le=100, strict=True)
    cursor: str | None = Field(default=None, min_length=1, max_length=256, pattern=r"^[A-Za-z0-9_-]+$")


class GetJobStatsRequest(HistoryFilters):
    group_by: Literal["host", "status", "story_id", "day"] = "host"
    limit: int = Field(default=50, ge=1, le=100, strict=True)


class CancelJobRequest(GetJobRequest):
    reason: str = Field(min_length=1, max_length=200)


class FileOperationRequest(StrictRequest):
    server: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    path: str = Field(min_length=1, max_length=4096)
    reason: str = Field(min_length=1, max_length=200)
    story_id: str | None = Field(default=None, min_length=1, max_length=80,
                                 pattern=r"^[^\s\x00-\x1F\x7F-\x9F]+$")
    base_dir: str | None = Field(default=None, max_length=4096)
    operation_id: str | None = Field(default=None, min_length=8, max_length=120,
                                     pattern=r"^[A-Za-z0-9_-]+$")


class TransferFileRequest(StrictRequest):
    """Opaque, dual-host binary relay: never accepts or returns file contents."""
    source_server: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    source_path: str = Field(min_length=1, max_length=4096)
    dest_server: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    dest_path: str = Field(min_length=1, max_length=4096)
    source_privileged: bool = Field(default=False, strict=True)
    dest_privileged: bool = Field(default=False, strict=True)
    mode: Literal["create", "overwrite"] = "create"
    create_parents: bool = Field(default=False, strict=True)
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    expected_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    wait_seconds: int = Field(default=30, ge=0, le=60, strict=True)
    timeout_seconds: int = Field(default=config.SSH_DEFAULT_TIMEOUT_SECONDS,
                                 ge=1, le=config.SSH_MAX_TIMEOUT_SECONDS, strict=True)
    reason: str = Field(min_length=1, max_length=200)
    story_id: str | None = Field(default=None, min_length=1, max_length=80,
                                 pattern=r"^[^\s\x00-\x1F\x7F-\x9F]+$")
    operation_id: str | None = Field(default=None, min_length=8, max_length=120,
                                     pattern=r"^[A-Za-z0-9_-]+$")

    @model_validator(mode="after")
    def valid_hosts_and_paths(self) -> Self:
        if self.source_server == self.dest_server:
            raise ValueError("Host-to-host transfer requires different approved hosts")
        if any("\x00" in p for p in (self.source_path, self.dest_path)):
            raise ValueError("File paths must not contain NUL")
        if self.mode == "create" and self.expected_sha256 is not None:
            raise ValueError("Destination preimage checksum applies only to overwrite")
        return self


class ReadFileRequest(FileOperationRequest):
    """Bounded text read with opaque continuation and optional full-file SHA."""
    cursor: str | None = Field(default=None, max_length=2048)
    start_line: int = Field(default=1, ge=1, strict=True)
    end_line: int | None = Field(default=None, ge=1, strict=True)
    max_bytes: int = Field(default=65536, ge=1, le=131072, strict=True)
    encoding: Literal["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"] = "utf-8"
    include_sha256: bool = False


class WriteFileRequest(FileOperationRequest):
    """In-place by default; replacement and append may create missing files."""
    content: str = Field(max_length=700000)
    mode: Literal["create", "replace", "append"] = "replace"
    create_parents: bool = False
    atomic: bool = False
    expected_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    encoding: Literal["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"] = "utf-8"
    newline: Literal["lf", "crlf"] | None = None
    include_sha256: bool = False


class ApplyPatchRequest(FileOperationRequest):
    """Multi-file Codex patch; request.path defaults to '.' for audit grouping."""
    path: str = "."
    patch: str = Field(min_length=20, max_length=700000)
    expected_hashes: dict[str, str] = Field(default_factory=dict, max_length=100)
    create_parents: bool = False
    atomic: bool = False
    include_sha256: bool = False
    dry_run: bool = False
    include_diff: bool = False
    max_diff_bytes: int = Field(default=8192, ge=1, le=16384, strict=True)
    encoding: Literal["utf-8", "utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"] | None = None
    newline: Literal["lf", "crlf"] | None = None


class ChatGPTFileRef(StrictRequest):
    """Native ChatGPT file parameter; signed URL is transient and never audited."""
    download_url: str = Field(min_length=12, max_length=8192)
    file_id: str = Field(min_length=1, max_length=1024)
    mime_type: str | None = Field(default=None, max_length=255)
    file_name: str | None = Field(default=None, max_length=255)


class UploadFileRequest(FileOperationRequest):
    """Upload an attached ChatGPT binary via bounded, staged SSH transfer."""
    file: ChatGPTFileRef
    mode: Literal["create", "overwrite"] = "create"
    create_parents: bool = False
    source_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    expected_sha256: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")


class DownloadFileRequest(FileOperationRequest):
    """Read one version-bound binary chunk as a tool response resource."""
    offset: int = Field(default=0, ge=0, strict=True)
    cursor: str | None = Field(default=None, max_length=2048)
    max_bytes: int = Field(default=65536, ge=1, le=65536, strict=True)
    include_sha256: bool = False


class FileOperationResponse(BaseModel):
    status: Literal["succeeded", "failed", "partial", "unknown"]
    operation_id: str | None = None
    history_id: str | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class PatchContextLine(BaseModel):
    line: int = Field(ge=1)
    text: str = Field(max_length=121)


class PatchConflictDiagnostic(BaseModel):
    """Safe reusable hunk diagnostics for apply and dry-run previews."""

    failure_kind: Literal[
        "missing_section", "context_mismatch", "eof_mismatch",
        "hash_mismatch", "missing_file",
    ]
    hunk: int | None = Field(default=None, ge=1)
    line_hint: int | None = Field(default=None, ge=1)
    expected_context: list[str] = Field(max_length=4)
    actual_excerpt: list[PatchContextLine] = Field(max_length=4)
    excerpt_available: bool


class PatchPathOutcome(BaseModel):
    path: str
    action: Literal["add", "update", "delete"]
    status: Literal["applied", "failed", "not_attempted", "applicable", "unchanged"]
    bytes: int = Field(ge=0)
    error_code: str | None = None
    failure_kind: str | None = None
    conflict: PatchConflictDiagnostic | None = None
    moved_to: str | None = None
    sha256: str | None = None
    hash_error_code: str | None = None
    added_lines: int | None = Field(default=None, ge=0)
    removed_lines: int | None = Field(default=None, ge=0)
    before_sha256: str | None = None
    prospective_sha256: str | None = None
    diff: str | None = None
    diff_truncated: bool | None = None


class PatchError(BaseModel):
    code: str
    message: str
    failed_path: str | None = None
    failure_kind: str | None = None
    conflict: PatchConflictDiagnostic | None = None


class PatchResult(BaseModel):
    ok: bool
    partial: bool
    unknown: bool | None = None
    bytes: int = Field(ge=0)
    outcomes: list[PatchPathOutcome]
    error: PatchError | None = None
    dry_run: bool | None = None
    applicability: Literal["applicable", "not_applicable"] | None = None
    summary: dict[str, Any] | None = None
    change_state: Literal["complete", "partial", "no_changes", "outcome_uncertain"] | None = None
    retry_guidance: Literal["none", "refresh_preconditions", "reconcile_before_retry"] | None = None
    preflight_completed: bool | None = None


class ApplyPatchResponse(BaseModel):
    status: Literal["succeeded", "failed", "partial", "unknown"]
    operation_id: str | None = None
    history_id: str | None = None
    result: PatchResult | None = None
    error: dict[str, Any] | None = None
    change_state: Literal["complete", "partial", "no_changes", "outcome_uncertain"] | None = None
    retry_guidance: Literal["none", "refresh_preconditions", "reconcile_before_retry"] | None = None


class ServerSummary(BaseModel):
    id: str
    label: str
    enabled: bool


class HostReadinessResponse(BaseModel):
    status: Literal["active", "offline", "retired"]
    sudo_ready: bool


class ListServersResponse(BaseModel):
    servers: dict[str, HostReadinessResponse]
    history_hosts: list[str] = Field(default_factory=list)


class JobSummary(BaseModel):
    """Complete safe job summary, shared by MCP and historical file events."""
    id: str
    server: str
    conversation_id: str | None = None
    status: JobStatus | Literal["partial", "unknown"]
    created_at: str
    updated_at: str | None = None
    mode: Literal["sync", "async", "file", "batch"] | None = None
    story_id: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    command: str | None = None
    argv_count: int | None = None
    command_sha256: str | None = None
    privileged: bool = False
    # Requested identity; root_started separately confirms wrapper startup.
    run_as: str | None = None
    root_started: bool | None = None
    failure_kind: str | None = None
    approval_status: str | None = None
    exit_code: int | None = None
    exit_accepted: bool | None = None
    effective_cwd: str | None = None
    elapsed_seconds: float | None = None
    output_bytes: int | None = None
    error: str | None = None
    cancellation_requested: bool | None = None
    record_kind: Literal["command", "file", "batch"] | None = None
    operation_kind: str | None = None
    path_summary: str | None = None
    byte_count: int | None = None
    error_code: str | None = None
    reason: str | None = None


class FileHistoryOutcome(BaseModel):
    path: str
    status: Literal["applied", "failed", "not_attempted"]
    bytes: int
    error_code: str | None = None


class TransferHistoryMetadata(BaseModel):
    """Only safe, fixed metadata in the read-only SSH audit history."""
    direction: Literal["upload", "download"]
    mode: Literal["create", "overwrite"] | None = None
    size: int | None = None
    offset: int | None = None
    next_offset: int | None = None
    sha256: str | None = None
    chunk_sha256: str | None = None
    eof: bool | None = None


class FileHistoryMetadata(BaseModel):
    outcomes: list[FileHistoryOutcome]
    transfer: TransferHistoryMetadata | None = None


class JobDetail(JobSummary):
    """Full authenticated history detail; file-operation content is metadata only."""
    command_preview: str | None = None
    request: dict[str, Any] | None = None
    terminal_command: str | None = None
    file_metadata: FileHistoryMetadata | None = None


class ExecuteCommandResponse(BaseModel):
    job: JobSummary


class GetJobResponse(BaseModel):
    job: JobDetail


class OutputChunk(BaseModel):
    stream: Literal["stdout", "stderr"]
    data_base64: str


class GetJobOutputResponse(BaseModel):
    job_id: str
    cursor: int
    next_cursor: int
    chunks: list[OutputChunk]
    truncated: bool
    status: JobStatus | Literal["partial", "unknown"]


class ListJobsResponse(BaseModel):
    jobs: list[JobSummary]
    next_cursor: str | None = None
    has_more: bool = False
    total: int


class JobStatsGroup(BaseModel):
    name: str | None
    count: int
    average_duration_seconds: float | None
    duration_sample_count: int


class GetJobStatsResponse(BaseModel):
    total: int
    status_counts: dict[str, int]
    failures: int
    transport_errors: int
    average_duration_seconds: float | None
    duration_sample_count: int
    group_by: Literal["host", "status", "story_id", "day"]
    groups: list[JobStatsGroup]
    groups_truncated: bool
    time_range: str
    retained_only: bool


class ServiceStatus(BaseModel):
    status: Literal["ready", "degraded"]
    version: str
    environment: str
    uptime_seconds: int


class StorageStatus(BaseModel):
    oauth_ready: bool
    audit_ready: bool
    retained_jobs: int | None


class JobActivityStatus(BaseModel):
    queued: int | None
    running: int | None
    failed_last_24h: int | None
    transport_errors_last_24h: int | None


class ServiceCapabilities(BaseModel):
    ssh_execution: bool
    durable_jobs: bool
    history_search: bool


class GetStatusResponse(BaseModel):
    service: ServiceStatus
    storage: StorageStatus
    jobs: JobActivityStatus
    capabilities: ServiceCapabilities


class CancelJobResponse(BaseModel):
    job: JobSummary
    cancellation_requested: bool


BatchStatus = Literal[
    "awaiting_approval", "queued", "running", "succeeded", "failed", "timed_out",
    "transport_error", "output_limit", "interrupted", "cancelled", "rejected", "denied",
]
BatchStepStatus = Literal[
    "not_attempted", "running", "succeeded", "failed", "timed_out",
    "transport_error", "output_limit", "unknown", "cancelled",
]


class BatchStepResponse(BaseModel):
    """Safe ordered step metadata; full output remains in get_job_output."""

    index: int = Field(ge=0, le=4)
    step_id: str
    status: BatchStepStatus
    result_status: str | None
    job_id: str | None
    command: str
    command_sha256: str
    exit_code: int | None
    exit_accepted: bool | None
    elapsed_seconds: float | None
    attempted: bool
    error: str | None = None
    output_unavailable: bool | None = None
    stdout: str | None = None
    stderr: str | None = None
    output_truncated: bool | None = None
    output_bytes: int | None = None
    output_next_cursor: int | None = None


class ExecuteCommandsResponse(BaseModel):
    """Completed/recoverable batch or bounded pre-execution rejection.

    Validation and authorization rejections have status=rejected,
    steps_attempted=0 and no batch_id. An accepted batch carries its
    durable batch_id and ordered step details for read-only recovery.
    """

    status: BatchStatus
    batch_id: str | None = None
    server: str | None = None
    story_id: str | None = None
    conversation_id: str | None = None
    reason: str | None = None
    failure_kind: str | None = None
    failed_step: int | None = None
    failed_field: str | None = None
    error: str | None = None
    steps_attempted: int | None = Field(default=None, ge=0, le=5)
    requested_cwd: str | None = None
    effective_cwd: str | None = None
    strict_bash: bool | None = None
    privileged: bool | None = None
    run_as: str | None = None
    stop_on_error: bool | None = None
    timeout_seconds: int | None = None
    total_steps: int | None = None
    steps: list[BatchStepResponse] | None = None
    next_cursor: int | None = None
    has_more: bool | None = None


class GetBatchResponse(ExecuteCommandsResponse):
    """Detailed actor-scoped batch: always has a durable ID and step page."""

    batch_id: str
    server: str
    reason: str
    strict_bash: bool
    stop_on_error: bool
    timeout_seconds: int = Field(ge=1, le=900)
    total_steps: int = Field(ge=1, le=5)
    steps: list[BatchStepResponse]
    has_more: bool


class BatchListItem(BaseModel):
    batch_id: str
    server: str
    story_id: str | None
    conversation_id: str | None = None
    status: BatchStatus
    privileged: bool = False
    run_as: str | None = None
    total_steps: int = Field(ge=1, le=5)
    created_at: float


class ListBatchesResponse(BaseModel):
    batches: list[BatchListItem]
    next_cursor: int | None


class CancelBatchResponse(BaseModel):
    batch_id: str
    cancellation_requested: bool
    status: BatchStatus


@dataclass(frozen=True, slots=True)
class ToolContract:
    name: str
    description: str
    request: type[StrictRequest]
    response: type[BaseModel]
    read_only: bool


# Keep the order stable to make generated schemas reviewable and versionable.
CONTRACTS: tuple[ToolContract, ...] = (
    ToolContract("list_servers", "List authorized aliases and their active, offline or retired readiness states.", ListServersRequest, ListServersResponse, True),
    ToolContract("get_status", "Read local service version, readiness and job state.", ListServersRequest, GetStatusResponse, True),
    ToolContract("execute_command", "Request an audited, allowlisted command job.", ExecuteCommandRequest, ExecuteCommandResponse, False),
    ToolContract("get_job", "Read the state of one job.", GetJobRequest, GetJobResponse, True),
    ToolContract("get_job_output", "Read a bounded output chunk.", GetJobOutputRequest, GetJobOutputResponse, True),
    ToolContract("list_jobs", "Search retained jobs with filters and cursor pagination.", ListJobsRequest, ListJobsResponse, True),
    ToolContract("get_job_stats", "Aggregate retained job outcomes and durations.", GetJobStatsRequest, GetJobStatsResponse, True),
    ToolContract("cancel_job", "Request cancellation of a running job.", CancelJobRequest, CancelJobResponse, False),
    ToolContract("execute_commands", "Run 1-5 bounded sequential commands with durable recovery.",
                 ExecuteCommandsRequest, ExecuteCommandsResponse, False),
    ToolContract("get_batch", "Read a paginated, actor-scoped batch and child job results.",
                 GetBatchRequest, GetBatchResponse, True),
    ToolContract("list_batches", "Discover retained actor-scoped batch IDs after disconnect.",
                 ListBatchesRequest, ListBatchesResponse, True),
    ToolContract("cancel_batch", "Cancel an active batch without retrying uncertain steps.",
                 CancelBatchRequest, CancelBatchResponse, False),
    ToolContract("read_file", "Read bounded text with a version-bound cursor and optional SHA-256.",
                 ReadFileRequest, FileOperationResponse, True),
    ToolContract("write_file", "Create, replace or append UTF text via authenticated SSH.",
                 WriteFileRequest, FileOperationResponse, False),
    ToolContract("apply_patch", "Apply or safely preview a Codex-style multi-file patch with bounded read-gated conflict diagnostics.",
                 ApplyPatchRequest, ApplyPatchResponse, False),
    ToolContract("upload_file", "Upload an attached binary with staged SHA-256 verified publication.",
                 UploadFileRequest, FileOperationResponse, False),
    ToolContract("download_file", "Download a bounded binary chunk as an MCP blob resource.",
                 DownloadFileRequest, FileOperationResponse, True),
)

CONTRACTS_BY_NAME: dict[str, ToolContract] = {entry.name: entry for entry in CONTRACTS}


def contract_document() -> dict[str, object]:
    """Return versioned static JSON schemas; does not register executable tools."""
    return {
        "contract_version": CONTRACT_VERSION,
        "status": "active",
        "tools": [
            {
                "name": item.name,
                "description": item.description,
                "readOnly": item.read_only,
                "inputSchema": item.request.model_json_schema(),
                "outputSchema": item.response.model_json_schema(),
            }
            for item in CONTRACTS
        ],
    }


def validate_request(name: str, params: object) -> StrictRequest:
    """Validate a proposed request offline, with no execution or side effects."""
    return CONTRACTS_BY_NAME[name].request.model_validate(params)


def main() -> None:
    print(json.dumps(contract_document(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
