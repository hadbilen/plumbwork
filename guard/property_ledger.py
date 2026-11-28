"""
guard/property_ledger.py — File-Hash-Bound Property Ledger with Planted-Bug Red Proofs
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero external dependencies: uses strictly the Python standard library.

Adapted in design from DeadInternetStudios/100x-engineer-skill (MIT License) for Plumbwork's
Python stdlib verification boundary (`verify/ledger.tsv` + `verify/red/<id>.txt`).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shlex
import signal
import subprocess
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from guard.paths import atomic_write_text, is_within, read_regular_file_nofollow

LEDGER_COLUMNS: Tuple[str, ...] = (
    "id",
    "kind",
    "property",
    "covers",
    "covers_hash",
    "command",
    "level",
    "red",
    "status",
    "checked_at",
    "commit",
    "ran_hash",
)

VALID_KINDS: Tuple[str, ...] = (
    "state",
    "transition",
    "precondition",
    "postcondition",
    "invariant",
    "liveness",
)
VALID_LEVELS: Tuple[str, ...] = ("exhaustive", "bounded", "sampled")
VALID_STORED_STATUSES: Tuple[str, ...] = ("unchecked", "passed", "holds", "broken", "waived")

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
RED_FAIL_RE = re.compile(r"^FAIL\s+\S", re.MULTILINE)
SHELL_OP_RE = re.compile(r"(?:&&|\|\||[;|&`><\n\r]|\$\()")
BLOCKED_SHELL_BINARIES = frozenset({
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "env",
})
BLOCKED_WINDOWS_SCRIPT_EXTS = (".bat", ".cmd")

MAX_COVERED_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_RED_FILE_BYTES = 1 * 1024 * 1024       # 1 MiB
MAX_OUTPUT_CAPTURE_BYTES = 64 * 1024       # 64 KiB
MIN_TIMEOUT_SECONDS = 1
MAX_TIMEOUT_SECONDS = 3600
DEFAULT_TIMEOUT_SECONDS = 120


class LedgerError(Exception):
    """Raised on corrupt ledger, missing required ledger, symlink/traversal, or unsafe execution."""


@dataclass
class RowEvaluation:
    id: str
    kind: str
    state: str
    property: str
    covers: List[str]
    level: str
    reason: str
    covers_hash: str
    current_hash: str


@dataclass
class RunOutcome:
    id: str
    passed: bool
    returncode: int
    state: str
    ran_hash: str
    stdout_tail: str
    stderr_tail: str
    timed_out: bool = False


def _utc_now(now: Optional[datetime] = None) -> str:
    dt = now or datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_cell(value: Any, *, field_name: str = "field", reject_control: bool = False) -> str:
    text = str("" if value is None else value)
    if "\x00" in text:
        raise LedgerError(f"NUL byte is prohibited in ledger {field_name}.")
    if reject_control and any(ch in text for ch in ("\t", "\r", "\n")):
        raise LedgerError(f"Tab or newline characters are prohibited in ledger {field_name}.")
    return re.sub(r"[\t\r\n]+", " ", text).strip()


def _normalize_rel_path(raw: str) -> str:
    cleaned = raw.strip().replace("\\", "/")
    if not cleaned:
        raise LedgerError("Covered path must not be empty.")
    if "\x00" in cleaned:
        raise LedgerError("NUL byte in covered path.")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        raise LedgerError(f"Covered path must be repository-relative: {raw!r}")
    parts = [p for p in cleaned.split("/") if p and p != "."]
    if not parts or any(p == ".." for p in parts):
        raise LedgerError(f"Path traversal ('..') is prohibited in covered path: {raw!r}")
    return "/".join(parts)


def split_covers(raw: str) -> List[str]:
    if not isinstance(raw, str):
        raise LedgerError("covers must be a comma-separated string of relative paths.")
    items: List[str] = []
    seen = set()
    for token in raw.split(","):
        tok = token.strip()
        if not tok:
            continue
        norm = _normalize_rel_path(tok)
        if norm not in seen:
            seen.add(norm)
            items.append(norm)
    return sorted(items)


def _check_no_symlink_components(root: Path, rel_parts: Sequence[str]) -> Path:
    cur = root
    for part in rel_parts:
        cur = cur / part
        if os.path.islink(cur):
            raise LedgerError(f"Refusing symlinked path inside workspace: {cur}")
    if not is_within(cur, root):
        raise LedgerError(f"Path escapes workspace root: {cur}")
    return cur


def _read_regular_file_safe(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Thin adapter over `guard.paths.read_regular_file_nofollow` (`O_NOFOLLOW | O_NONBLOCK`)."""
    status, data, detail = read_regular_file_nofollow(path, max_bytes=max_bytes)
    if status == "ok" and data is not None:
        return data
    if status == "missing":
        raise FileNotFoundError(str(path))
    if status == "symlink":
        raise LedgerError(f"Refusing symlinked {label}: {path}")
    if status == "not_regular":
        raise LedgerError(f"Refusing non-regular {label} (directory/FIFO/device): {path}")
    if status == "oversized":
        raise LedgerError(f"{label} exceeds size limit ({max_bytes} bytes): {path}")
    raise LedgerError(f"Cannot safely read {label} ({path}): {detail or status}")


def _git_head_short(root: Path) -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            sha = proc.stdout.strip()
            if re.fullmatch(r"[0-9a-fA-F]{4,40}", sha):
                return sha
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def _validate_command(command: str, *, allow_shell: bool = False) -> List[str]:
    cmd = _clean_cell(command, field_name="command", reject_control=True)
    if not cmd:
        raise LedgerError("Property check command must not be empty.")
    if not allow_shell and SHELL_OP_RE.search(cmd):
        raise LedgerError(
            "Shell control operators (;, &, &&, ||, |, `, $(, >, <, newline) are blocked by default; "
            "pass --allow-shell only for trusted commands."
        )
    if allow_shell:
        return [cmd]
    try:
        argv = shlex.split(cmd)
    except ValueError as exc:
        raise LedgerError(f"Malformed command syntax: {exc}") from exc
    if not argv:
        raise LedgerError("Property check command parsed to empty argv.")
    exe_base = re.split(r"[/\\]", argv[0])[-1].lower()
    if exe_base in BLOCKED_SHELL_BINARIES or exe_base.endswith(BLOCKED_WINDOWS_SCRIPT_EXTS):
        raise LedgerError(
            f"Shell interpreter or batch target {argv[0]!r} is blocked without --allow-shell; "
            "invoke the test runner executable directly or pass --allow-shell explicitly."
        )
    return argv


def _drain_pipe_tail(stream: Any, max_bytes: int, sink: List[bytes]) -> None:
    """Reads `stream` to EOF keeping only the last `max_bytes` bytes in memory."""
    buf = bytearray()
    try:
        while True:
            chunk = stream.read(16384)
            if not chunk:
                break
            if len(chunk) >= max_bytes:
                buf = bytearray(chunk[-max_bytes:])
            else:
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    del buf[: len(buf) - max_bytes]
    except OSError:
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass
    sink.append(bytes(buf))


def _execute_bounded(
    argv: List[str],
    *,
    cwd: Path,
    allow_shell: bool,
    timeout: int,
) -> Tuple[int, str, str, bool]:
    """Executes a property check with process-group isolation and bounded tail capture."""
    popen_kwargs: Dict[str, Any] = {
        "cwd": str(cwd),
        "shell": allow_shell,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    try:
        proc = subprocess.Popen(argv[0] if allow_shell else argv, **popen_kwargs)
    except OSError as exc:
        return 127, "", str(exc), False

    out_sink: List[bytes] = []
    err_sink: List[bytes] = []
    t_out = threading.Thread(target=_drain_pipe_tail, args=(proc.stdout, MAX_OUTPUT_CAPTURE_BYTES, out_sink), daemon=True)
    t_err = threading.Thread(target=_drain_pipe_tail, args=(proc.stderr, MAX_OUTPUT_CAPTURE_BYTES, err_sink), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        rc = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        rc = 124
        if os.name != "nt":
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    proc.kill()
                except OSError:
                    pass
        else:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    t_out.join(timeout=2.0)
    t_err.join(timeout=2.0)
    out_tail = (out_sink[0] if out_sink else b"").decode("utf-8", errors="replace")
    err_tail = (err_sink[0] if err_sink else b"").decode("utf-8", errors="replace")
    if timed_out:
        err_tail = f"{err_tail}\n[TIMEOUT] exceeded {timeout}s".strip()
    return rc, out_tail, err_tail, timed_out


@contextlib.contextmanager
def _exclusive_file_lock(lock_path: Path) -> Iterator[None]:
    """Cross-platform exclusive lockfile for serializing `verify/ledger.tsv` mutations."""
    if os.path.islink(lock_path):
        raise LedgerError(f"Refusing symlinked lockfile: {lock_path}")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.fspath(lock_path), flags, 0o644)
    except OSError as exc:
        raise LedgerError(f"Cannot open ledger lockfile ({lock_path}): {exc}") from exc
    try:
        if os.name == "nt":
            import msvcrt  # type: ignore[import-not-found]

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt  # type: ignore[import-not-found]

                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
    finally:
        os.close(fd)


class PropertyLedger:
    """Manages git-tracked `verify/ledger.tsv` and planted-bug red proofs under `verify/red/`."""

    def __init__(self, root: Optional[Path] = None) -> None:
        raw_root = Path(root) if root is not None else Path.cwd()
        self.root = raw_root.resolve()
        self.verify_dir = self.root / "verify"
        self.ledger_path = self.verify_dir / "ledger.tsv"
        self.red_dir = self.verify_dir / "red"
        self.lock_path = self.verify_dir / ".ledger.lock"

    def _ensure_safe_verify_tree(self, *, create: bool = False) -> None:
        if os.path.islink(self.verify_dir):
            raise LedgerError(f"Refusing symlinked verify/ directory: {self.verify_dir}")
        if self.verify_dir.exists() and not self.verify_dir.is_dir():
            raise LedgerError(f"verify path is not a directory: {self.verify_dir}")
        if create and not self.verify_dir.exists():
            try:
                self.verify_dir.mkdir(mode=0o755, parents=False, exist_ok=True)
            except OSError as exc:
                raise LedgerError(f"Cannot create verify/ directory ({self.verify_dir}): {exc}") from exc
        if os.path.islink(self.ledger_path):
            raise LedgerError(f"Refusing symlinked ledger file: {self.ledger_path}")
        if os.path.islink(self.red_dir):
            raise LedgerError(f"Refusing symlinked verify/red directory: {self.red_dir}")
        if self.red_dir.exists() and not self.red_dir.is_dir():
            raise LedgerError(f"verify/red path is not a directory: {self.red_dir}")

    def exists(self) -> bool:
        if os.path.islink(self.verify_dir) or os.path.islink(self.ledger_path):
            raise LedgerError(f"Refusing symlinked ledger path under {self.verify_dir}")
        return self.ledger_path.is_file()

    def hash_covers(self, covers: Sequence[str]) -> Tuple[str, List[str]]:
        """
        Computes a canonical 16-hex SHA-256 digest over sorted relative regular files.
        Returns `(digest, problems)`; `digest` is `""` whenever any covered path is invalid/missing.
        """
        if not covers:
            return "", ["no covered paths listed"]
        problems: List[str] = []
        pairs: List[Tuple[str, str]] = []
        for raw_rel in sorted(set(covers)):
            try:
                norm = _normalize_rel_path(raw_rel)
                target = _check_no_symlink_components(self.root, norm.split("/"))
            except LedgerError as exc:
                problems.append(str(exc))
                continue
            try:
                data = _read_regular_file_safe(target, max_bytes=MAX_COVERED_FILE_BYTES, label="covered file")
            except FileNotFoundError:
                problems.append(f"covered path missing: {norm}")
                continue
            except LedgerError as exc:
                problems.append(str(exc))
                continue
            file_digest = hashlib.sha256(data).hexdigest()
            pairs.append((norm, file_digest))
        if problems:
            return "", problems
        payload = ("\n".join(f"{rel}\x00{digest}" for rel, digest in pairs) + "\n").encode("utf-8")
        return hashlib.sha256(payload).hexdigest()[:16], []

    def check_red_proof(self, row_id: str, red_rel: Optional[str] = None) -> Tuple[bool, str]:
        expected_rel = f"verify/red/{row_id}.txt"
        try:
            rel = _normalize_rel_path(red_rel) if red_rel and red_rel.strip() else expected_rel
            if rel != expected_rel:
                return False, f"red proof path must match {expected_rel!r}, got {rel!r}"
            self._ensure_safe_verify_tree(create=False)
            target = _check_no_symlink_components(self.root, rel.split("/"))
            data = _read_regular_file_safe(target, max_bytes=MAX_RED_FILE_BYTES, label="red proof")
        except FileNotFoundError:
            return (
                False,
                f"missing planted-bug red proof at {expected_rel}; seed a defect, record output with a `FAIL <reason>` line",
            )
        except LedgerError as exc:
            return False, str(exc)
        text = data.decode("utf-8", errors="replace")
        if not RED_FAIL_RE.search(text):
            return False, f"{expected_rel} has no `FAIL <reason>` line proving the check catches a planted defect"
        return True, ""

    def read_rows(self) -> List[Dict[str, str]]:
        self._ensure_safe_verify_tree(create=False)
        try:
            raw_bytes = _read_regular_file_safe(self.ledger_path, max_bytes=MAX_COVERED_FILE_BYTES, label="ledger")
        except FileNotFoundError as exc:
            raise LedgerError(f"Property ledger not found: {self.ledger_path}") from exc
        try:
            text = raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise LedgerError(f"Corrupt non-UTF-8 property ledger ({self.ledger_path}): {exc}") from exc
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            raise LedgerError(f"Property ledger is empty (missing header): {self.ledger_path}")
        header = tuple(lines[0].split("\t"))
        if header != LEDGER_COLUMNS:
            raise LedgerError(
                f"Corrupt property ledger header in {self.ledger_path}: expected {LEDGER_COLUMNS!r}, got {header!r}"
            )
        rows: List[Dict[str, str]] = []
        seen_ids = set()
        for line_no, line in enumerate(lines[1:], start=2):
            cells = line.split("\t")
            if len(cells) != len(LEDGER_COLUMNS):
                raise LedgerError(
                    f"Malformed row at {self.ledger_path}:{line_no}: expected {len(LEDGER_COLUMNS)} columns, got {len(cells)}"
                )
            row = dict(zip(LEDGER_COLUMNS, cells))
            row_id = row["id"]
            if not ID_RE.fullmatch(row_id):
                raise LedgerError(f"Invalid property id at {self.ledger_path}:{line_no}: {row_id!r}")
            if row_id in seen_ids:
                raise LedgerError(f"Duplicate property id in {self.ledger_path}: {row_id!r}")
            seen_ids.add(row_id)
            if row["kind"] not in (*VALID_KINDS, "waived"):
                raise LedgerError(f"Invalid kind at {self.ledger_path}:{line_no}: {row['kind']!r}")
            if row["kind"] != "waived" and row["level"] not in VALID_LEVELS:
                raise LedgerError(f"Invalid level at {self.ledger_path}:{line_no}: {row['level']!r}")
            if row["status"] not in VALID_STORED_STATUSES:
                raise LedgerError(f"Invalid status at {self.ledger_path}:{line_no}: {row['status']!r}")
            rows.append(row)
        return rows

    def write_rows(self, rows: Sequence[Dict[str, str]]) -> None:
        self._ensure_safe_verify_tree(create=True)
        out_lines = ["\t".join(LEDGER_COLUMNS)]
        for row in rows:
            cells = [_clean_cell(row.get(col, ""), field_name=col) for col in LEDGER_COLUMNS]
            out_lines.append("\t".join(cells))
        content = "\n".join(out_lines) + "\n"
        try:
            atomic_write_text(self.ledger_path, content, mode=0o644)
        except OSError as exc:
            raise LedgerError(f"Cannot write property ledger ({self.ledger_path}): {exc}") from exc

    def evaluate_row(self, row: Dict[str, str]) -> RowEvaluation:
        row_id = row["id"]
        kind = row["kind"]
        try:
            covers = split_covers(row.get("covers", ""))
        except LedgerError as exc:
            return RowEvaluation(
                id=row_id,
                kind=kind,
                state="stale",
                property=row.get("property", ""),
                covers=[],
                level=row.get("level", ""),
                reason=str(exc),
                covers_hash=row.get("covers_hash", ""),
                current_hash="",
            )

        current_hash, cover_problems = self.hash_covers(covers)

        # 1. Waived rows: stale if any covered file is missing/symlinked/escaping; content changes stay waived.
        if kind == "waived":
            if cover_problems:
                return RowEvaluation(
                    id=row_id,
                    kind=kind,
                    state="stale",
                    property=row.get("property", ""),
                    covers=covers,
                    level="",
                    reason="; ".join(cover_problems),
                    covers_hash=row.get("covers_hash", ""),
                    current_hash="",
                )
            return RowEvaluation(
                id=row_id,
                kind=kind,
                state="waived",
                property=row.get("property", ""),
                covers=covers,
                level="",
                reason=row.get("property", ""),
                covers_hash=row.get("covers_hash", ""),
                current_hash=current_hash,
            )

        # 2. Broken: last run failed.
        if row.get("status") == "broken":
            commit = row.get("commit", "") or "working-tree"
            return RowEvaluation(
                id=row_id,
                kind=kind,
                state="broken",
                property=row.get("property", ""),
                covers=covers,
                level=row.get("level", ""),
                reason=f"last run failed ({commit})",
                covers_hash=row.get("covers_hash", ""),
                current_hash=current_hash,
            )

        # 3. Stale: covered path invalid/missing or source hash changed after last sync.
        if cover_problems:
            return RowEvaluation(
                id=row_id,
                kind=kind,
                state="stale",
                property=row.get("property", ""),
                covers=covers,
                level=row.get("level", ""),
                reason="; ".join(cover_problems),
                covers_hash=row.get("covers_hash", ""),
                current_hash="",
            )
        if current_hash != row.get("covers_hash", ""):
            return RowEvaluation(
                id=row_id,
                kind=kind,
                state="stale",
                property=row.get("property", ""),
                covers=covers,
                level=row.get("level", ""),
                reason="covered code changed since last sync; re-run and ledger-sync after inspecting diff",
                covers_hash=row.get("covers_hash", ""),
                current_hash=current_hash,
            )

        status = row.get("status", "unchecked")
        # 4. Unproven: check passed or marked holds, but planted-bug red proof is missing or lacks `FAIL <reason>`.
        if status in ("passed", "holds"):
            red_ok, red_reason = self.check_red_proof(row_id, row.get("red", ""))
            if not red_ok:
                return RowEvaluation(
                    id=row_id,
                    kind=kind,
                    state="unproven",
                    property=row.get("property", ""),
                    covers=covers,
                    level=row.get("level", ""),
                    reason=red_reason,
                    covers_hash=row.get("covers_hash", ""),
                    current_hash=current_hash,
                )

        # 5. Holds: synced green row with matching covers_hash and valid red proof.
        if status == "holds":
            return RowEvaluation(
                id=row_id,
                kind=kind,
                state="holds",
                property=row.get("property", ""),
                covers=covers,
                level=row.get("level", ""),
                reason="",
                covers_hash=row.get("covers_hash", ""),
                current_hash=current_hash,
            )

        # 6. Unchecked: never run, or passed locally with red proof awaiting explicit ledger-sync.
        reason = "passed; run ledger-sync to promote to holds" if status == "passed" else "never run"
        return RowEvaluation(
            id=row_id,
            kind=kind,
            state="unchecked",
            property=row.get("property", ""),
            covers=covers,
            level=row.get("level", ""),
            reason=reason,
            covers_hash=row.get("covers_hash", ""),
            current_hash=current_hash,
        )

    def add_row(
        self,
        *,
        row_id: str,
        kind: str,
        prop: str,
        covers_raw: str,
        command: str,
        level: str,
        allow_shell: bool = False,
    ) -> Dict[str, str]:
        if not ID_RE.fullmatch(row_id or ""):
            raise LedgerError(f"Invalid id {row_id!r}: must match ^[a-z0-9][a-z0-9-]{{0,63}}$.")
        if kind not in VALID_KINDS:
            raise LedgerError(f"Invalid kind {kind!r}: expected one of {', '.join(VALID_KINDS)}.")
        if level not in VALID_LEVELS:
            raise LedgerError(f"Invalid level {level!r}: expected one of {', '.join(VALID_LEVELS)}.")
        clean_prop = _clean_cell(prop, field_name="property", reject_control=True)
        if len(clean_prop) < 12:
            raise LedgerError("property must be a plain sentence of at least 12 characters.")
        _validate_command(command, allow_shell=allow_shell)
        clean_cmd = _clean_cell(command, field_name="command", reject_control=True)

        covers = split_covers(covers_raw)
        covers_hash, problems = self.hash_covers(covers)
        if problems:
            raise LedgerError("; ".join(problems))

        self._ensure_safe_verify_tree(create=True)
        with _exclusive_file_lock(self.lock_path):
            rows = self.read_rows() if self.exists() else []
            if any(r["id"] == row_id for r in rows):
                raise LedgerError(f"Property id {row_id!r} already exists in {self.ledger_path}.")
            new_row = {
                "id": row_id,
                "kind": kind,
                "property": clean_prop,
                "covers": ",".join(covers),
                "covers_hash": covers_hash,
                "command": clean_cmd,
                "level": level,
                "red": f"verify/red/{row_id}.txt",
                "status": "unchecked",
                "checked_at": "",
                "commit": "",
                "ran_hash": "",
            }
            rows.append(new_row)
            self.write_rows(rows)
        return new_row

    def waive_paths(self, *, covers_raw: str, why: str, now: Optional[datetime] = None) -> List[Dict[str, str]]:
        reason = _clean_cell(why, field_name="why", reject_control=True)
        if len(reason) < 12:
            raise LedgerError("--why must state a reason of at least 12 characters.")
        covers = split_covers(covers_raw)
        if not covers:
            raise LedgerError("--covers must list at least one relative file path.")

        hashes: Dict[str, str] = {}
        for rel in covers:
            file_hash, problems = self.hash_covers([rel])
            if problems:
                raise LedgerError("; ".join(problems))
            hashes[rel] = file_hash

        ts = _utc_now(now)
        commit = _git_head_short(self.root)
        added: List[Dict[str, str]] = []
        self._ensure_safe_verify_tree(create=True)
        with _exclusive_file_lock(self.lock_path):
            rows = self.read_rows() if self.exists() else []
            existing_ids = {r["id"] for r in rows}
            for rel in covers:
                slug = re.sub(r"[^a-z0-9]+", "-", rel.lower()).strip("-")[:50] or "file"
                base_id = f"waived-{slug}"
                if any(r["kind"] == "waived" and r["covers"] == rel for r in rows):
                    continue
                cand_id = base_id
                suffix = 2
                while cand_id in existing_ids:
                    cand_id = f"{base_id[:58]}-{suffix}"
                    suffix += 1
                existing_ids.add(cand_id)
                row = {
                    "id": cand_id,
                    "kind": "waived",
                    "property": reason,
                    "covers": rel,
                    "covers_hash": hashes[rel],
                    "command": "",
                    "level": "",
                    "red": "",
                    "status": "waived",
                    "checked_at": ts,
                    "commit": commit,
                    "ran_hash": "",
                }
                rows.append(row)
                added.append(row)
            self.write_rows(rows)
        return added

    def run_rows(
        self,
        *,
        row_id: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        allow_shell: bool = False,
        now: Optional[datetime] = None,
    ) -> List[RunOutcome]:
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not (MIN_TIMEOUT_SECONDS <= timeout <= MAX_TIMEOUT_SECONDS):
            raise LedgerError(f"--timeout must be an integer between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS} seconds.")
        initial_rows = self.read_rows()
        targets = [r for r in initial_rows if (row_id is None or r["id"] == row_id)]
        if row_id is not None and not targets:
            raise LedgerError(f"Property id not found: {row_id!r}")

        # Pre-validate all runnable rows before executing subprocesses.
        runnable: List[Tuple[Dict[str, str], str, List[str]]] = []
        for row in targets:
            if row["kind"] == "waived":
                continue
            covers = split_covers(row["covers"])
            pre_hash, problems = self.hash_covers(covers)
            if problems:
                raise LedgerError(f"Cannot run property {row['id']!r}: {'; '.join(problems)}")
            argv = _validate_command(row["command"], allow_shell=allow_shell)
            runnable.append((row, pre_hash, argv))

        if not runnable:
            if row_id is not None:
                raise LedgerError(f"Property {row_id!r} is waived and has no runnable command.")
            raise LedgerError("Ledger contains 0 runnable (non-waived) property rows.")

        commit = _git_head_short(self.root)
        updates: Dict[str, Dict[str, str]] = {}
        raw_results: List[Tuple[str, bool, int, str, str, str, bool]] = []

        for row, pre_hash, argv in runnable:
            ts = _utc_now(now)
            rc, out_tail, err_tail, timed_out = _execute_bounded(
                argv,
                cwd=self.root,
                allow_shell=allow_shell,
                timeout=timeout,
            )
            passed = rc == 0 and not timed_out
            updates[row["id"]] = {
                "checked_at": ts,
                "commit": commit,
                "ran_hash": pre_hash,
                "_passed": "1" if passed else "0",
            }
            raw_results.append((row["id"], passed, rc, pre_hash, out_tail, err_tail, timed_out))

        # Re-read under exclusive lock and merge ONLY the executed row IDs so concurrent runs cannot clobber sibling rows.
        self._ensure_safe_verify_tree(create=True)
        outcomes: List[RunOutcome] = []
        with _exclusive_file_lock(self.lock_path):
            fresh_rows = self.read_rows()
            fresh_by_id = {r["id"]: r for r in fresh_rows}
            for rid, passed, rc, pre_hash, out_tail, err_tail, timed_out in raw_results:
                row = fresh_by_id.get(rid)
                if row is None:
                    continue
                upd = updates[rid]
                row["checked_at"] = upd["checked_at"]
                row["commit"] = upd["commit"]
                row["ran_hash"] = upd["ran_hash"]
                if passed:
                    red_ok, _ = self.check_red_proof(rid, row.get("red", ""))
                    if row.get("status") == "holds" and pre_hash == row.get("covers_hash", "") and red_ok:
                        row["status"] = "holds"
                    else:
                        row["status"] = "passed"
                else:
                    row["status"] = "broken"
                ev = self.evaluate_row(row)
                outcomes.append(
                    RunOutcome(
                        id=rid,
                        passed=passed,
                        returncode=rc,
                        state=ev.state,
                        ran_hash=pre_hash,
                        stdout_tail=out_tail,
                        stderr_tail=err_tail,
                        timed_out=timed_out,
                    )
                )
            self.write_rows(fresh_rows)
        return outcomes

    def sync_row(
        self,
        *,
        row_id: str,
        note: str,
        now: Optional[datetime] = None,
    ) -> Tuple[bool, str, Optional[RowEvaluation]]:
        clean_note = _clean_cell(note, field_name="note", reject_control=True)
        if len(clean_note) < 8:
            raise LedgerError("--note must explain the verified sync in at least 8 characters.")
        self._ensure_safe_verify_tree(create=False)
        with _exclusive_file_lock(self.lock_path):
            rows = self.read_rows()
            row = next((r for r in rows if r["id"] == row_id), None)
            if row is None:
                raise LedgerError(f"Property id not found: {row_id!r}")
            if row["kind"] == "waived":
                return False, f"Property {row_id!r} is waived and does not require sync.", self.evaluate_row(row)

            covers = split_covers(row["covers"])
            current_hash, problems = self.hash_covers(covers)
            if problems:
                return False, "; ".join(problems), self.evaluate_row(row)
            if row.get("status") not in ("passed", "holds"):
                return (
                    False,
                    f"Property {row_id!r} has status={row.get('status')!r}; run ledger-run successfully before ledger-sync.",
                    self.evaluate_row(row),
                )
            if row.get("ran_hash", "") != current_hash:
                return (
                    False,
                    f"Property {row_id!r} was not run against current code (ran_hash={row.get('ran_hash')!r}, current={current_hash!r}); re-run ledger-run first.",
                    self.evaluate_row(row),
                )
            red_ok, red_reason = self.check_red_proof(row_id, row.get("red", ""))
            if not red_ok:
                return False, f"Cannot sync unproven property {row_id!r}: {red_reason}", self.evaluate_row(row)

            row["covers_hash"] = current_hash
            row["status"] = "holds"
            row["checked_at"] = _utc_now(now)
            row["commit"] = _git_head_short(self.root)
            self.write_rows(rows)
            return True, f"Synced {row_id!r} -> holds (hash={current_hash}; note={clean_note})", self.evaluate_row(row)

    def status_report(self, *, file_filter: Optional[str] = None) -> Dict[str, Any]:
        rows = self.read_rows()
        norm_filter = _normalize_rel_path(file_filter) if file_filter else None
        evals: List[RowEvaluation] = []
        for row in rows:
            ev = self.evaluate_row(row)
            if norm_filter is not None and norm_filter not in ev.covers:
                continue
            evals.append(ev)

        counts = {"holds": 0, "waived": 0, "stale": 0, "broken": 0, "unproven": 0, "unchecked": 0}
        for ev in evals:
            counts[ev.state] = counts.get(ev.state, 0) + 1

        failing = [ev for ev in evals if ev.state not in ("holds", "waived")]
        ok = len(evals) > 0 and len(failing) == 0

        return {
            "root": str(self.root),
            "ledger": str(self.ledger_path),
            "file_filter": norm_filter,
            "total": len(evals),
            "counts": counts,
            "ok": ok,
            "rows": [asdict(ev) for ev in evals],
        }
