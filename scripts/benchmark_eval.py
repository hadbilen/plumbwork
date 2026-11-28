#!/usr/bin/env python3
"""
scripts/benchmark_eval.py — Automated Blinded A/B Benchmark Pair Builder & Statistical Scorer
Part of Plumbwork (https://github.com/tozhax/plumbwork)
Zero external dependencies: uses strictly the Python standard library.

Design concepts (order-swapped blinding, content leak scanning, local HMAC sealing, exact sign test,
Wilson 95% CI, and same-family self-review detection) adapted from DeadInternetStudios/100x-engineer-skill
(MIT License) for Plumbwork's `docs/benchmark-protocol.md`.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import shutil
import stat
import statistics
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guard.paths import read_regular_file_nofollow  # noqa: E402

TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
WILSON_Z_95 = 1.959963984540054

MAX_SINGLE_FILE_BYTES = 25 * 1024 * 1024  # 25 MiB
MAX_TREE_BYTES = 100 * 1024 * 1024        # 100 MiB
MAX_TREE_FILES = 5000

STRIPPED_NAMES = frozenset({
    "tasks.md",
    "HANDOFF.md",
    "walkthrough.md",
    "MISTAKES.md",
    ".git",
    "node_modules",
    "__pycache__",
})

DEFAULT_LEAK_MARKERS: Tuple[str, ...] = (
    "plumbwork",
    "plumb-guard",
    "agy-guard",
    "harness-on",
    "harness-off",
    "condition a",
    "condition b",
    "bench/bm-",
)

ALWAYS_FORBIDDEN_VERDICT_MARKERS: Tuple[str, ...] = (
    "key.json",
    "audit.key",
    "skill-on",
    "skill-off",
)

REQUIRED_LEDGER_KEYS: Tuple[str, ...] = (
    "task_id",
    "tier",
    "condition",
    "repo",
    "base_sha",
    "model",
    "acceptance_pass",
    "rule9_intact",
    "stop_gate_strikes",
    "auditor_confirmed_defects",
    "user_corrections",
    "wall_clock_sec",
    "total_tokens",
)

_EFFORT_SUFFIX_RE = re.compile(
    r"(?:\s*\((?:xhigh|high|medium|low|max|fast|mini)\)|(?:[-_](?:xhigh|high|medium|low|max|fast|mini)))\s*$",
    re.IGNORECASE,
)

_MODEL_FAMILY_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bgemini\b", re.IGNORECASE), "gemini"),
    (re.compile(r"\bclaude\b", re.IGNORECASE), "claude"),
    (re.compile(r"\bgpt(?:[- ]?\d|\b)", re.IGNORECASE), "gpt"),
    (re.compile(r"\bo[134](?:[- ]?(?:mini|pro|high))?\b", re.IGNORECASE), "openai-o"),
    (re.compile(r"\bllama\b", re.IGNORECASE), "llama"),
    (re.compile(r"\bqwen\b", re.IGNORECASE), "qwen"),
    (re.compile(r"\bdeepseek\b", re.IGNORECASE), "deepseek"),
    (re.compile(r"\bmistral\b", re.IGNORECASE), "mistral"),
    (re.compile(r"\bgrok\b", re.IGNORECASE), "grok"),
    (re.compile(r"\bmuse\b", re.IGNORECASE), "muse"),
    (re.compile(r"\bcomposer\b", re.IGNORECASE), "composer"),
)


class BenchmarkError(Exception):
    """Raised on CLI usage, missing files, or invalid paths (exit 2)."""


class IntegrityError(Exception):
    """Raised on leaks, tampered seals, or invalid schemas (exit 1)."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hmac_hex(key: str, payload: bytes) -> str:
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _safe_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _verify_private_dir(priv_dir: Path, *, create: bool = False) -> None:
    if os.path.islink(priv_dir):
        raise BenchmarkError(f"Refusing symlinked private directory: {priv_dir}")
    if not priv_dir.exists():
        if not create:
            raise BenchmarkError(f"Private directory not found: {priv_dir}")
        try:
            priv_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
        except OSError as exc:
            raise BenchmarkError(f"Cannot create private directory ({priv_dir}): {exc}") from exc
    st = os.lstat(priv_dir)
    if not stat.S_ISDIR(st.st_mode):
        raise BenchmarkError(f"Private path is not a directory: {priv_dir}")
    if os.name != "nt":
        if hasattr(os, "getuid") and st.st_uid != os.getuid():
            raise BenchmarkError(f"Private directory {priv_dir} is not owned by the current user.")
        if stat.S_IMODE(st.st_mode) & 0o077:
            try:
                os.chmod(priv_dir, 0o700)
                st = os.lstat(priv_dir)
            except OSError as exc:
                raise BenchmarkError(f"Cannot restrict permissions on {priv_dir} to 0o700: {exc}") from exc
            if stat.S_IMODE(st.st_mode) & 0o077:
                raise BenchmarkError(f"Private directory {priv_dir} retains group/world permissions.")


def _atomic_write_text_strict(path: Path, content: str, *, mode: int, private_parent: bool = False) -> None:
    if os.path.islink(path):
        raise BenchmarkError(f"Refusing symlinked output file: {path}")
    if private_parent:
        _verify_private_dir(path.parent, create=True)
    else:
        if os.path.islink(path.parent):
            raise BenchmarkError(f"Refusing symlinked parent directory: {path.parent}")
        path.parent.mkdir(parents=True, exist_ok=True)

    data = content.encode("utf-8")
    tmp_path: Optional[str] = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
        try:
            if os.name != "nt":
                os.fchmod(fd, mode)
            view = memoryview(data)
            written = 0
            while written < len(view):
                n = os.write(fd, view[written:])
                if n <= 0:
                    raise OSError("Short write while persisting file")
                written += n
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, path)
        tmp_path = None
    except OSError as exc:
        raise BenchmarkError(f"Failed to write {path}: {exc}") from exc
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def _read_regular_bytes(path: Path, *, max_bytes: int, label: str) -> bytes:
    """Reads a regular non-symlink file via `guard.paths.read_regular_file_nofollow` (`O_NOFOLLOW | O_NONBLOCK`)."""
    status, data, detail = read_regular_file_nofollow(path, max_bytes=max_bytes)
    if status == "ok" and data is not None:
        return data
    if status == "missing":
        raise BenchmarkError(f"{label} not found: {path}")
    if status == "oversized":
        raise IntegrityError(f"{label} exceeds {max_bytes} bytes: {path}")
    if status == "symlink":
        raise IntegrityError(f"Refusing symlinked {label}: {path}")
    if status == "not_regular":
        raise IntegrityError(f"Refusing non-regular {label}: {path}")
    raise BenchmarkError(f"Cannot read {label} ({path}): {detail or status}")


@contextlib.contextmanager
def _exclusive_private_lock(priv_dir: Path) -> Iterator[None]:
    _verify_private_dir(priv_dir, create=True)
    lock_path = priv_dir / ".lock"
    if os.path.islink(lock_path):
        raise BenchmarkError(f"Refusing symlinked lockfile: {lock_path}")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.fspath(lock_path), flags, 0o600)
    except OSError as exc:
        raise BenchmarkError(f"Cannot open campaign lockfile ({lock_path}): {exc}") from exc
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


def canonical_model_family(model_name: str) -> str:
    """Extracts a canonical vendor/model family for same-family self-review detection."""
    cleaned = (model_name or "").strip()
    if not cleaned:
        return ""
    while True:
        stripped = _EFFORT_SUFFIX_RE.sub("", cleaned).strip()
        if stripped == cleaned:
            break
        cleaned = stripped
    for pattern, family in _MODEL_FAMILY_PATTERNS:
        if pattern.search(cleaned):
            return family
    return re.sub(r"[^a-z0-9]+", "-", cleaned.lower()).strip("-")


def is_same_model_family(builder_model: str, judge_model: str) -> bool:
    b_fam = canonical_model_family(builder_model)
    j_fam = canonical_model_family(judge_model)
    return bool(b_fam and j_fam and b_fam == j_fam)


def exact_two_sided_sign_test(wins: int, total_decisive: int) -> float:
    """Computes exact two-sided binomial sign-test p-value using integer `math.comb`."""
    if total_decisive <= 0:
        return 1.0
    k = min(wins, total_decisive - wins)
    tail = sum(math.comb(total_decisive, i) for i in range(0, k + 1))
    return min(1.0, (2.0 * tail) / float(1 << total_decisive))


def wilson_95_interval(wins: int, total_decisive: int) -> Optional[Tuple[float, float]]:
    """Computes Wilson score 95% confidence interval for `wins / total_decisive`, or None if n == 0."""
    if total_decisive <= 0:
        return None
    n = float(total_decisive)
    p_hat = float(wins) / n
    z2 = WILSON_Z_95 * WILSON_Z_95
    denom = 1.0 + z2 / n
    center = (p_hat + z2 / (2.0 * n)) / denom
    margin = (WILSON_Z_95 * math.sqrt((p_hat * (1.0 - p_hat) + z2 / (4.0 * n)) / n)) / denom
    return (round(max(0.0, center - margin), 4), round(min(1.0, center + margin), 4))


def _hash_submission_tree(root: Path) -> str:
    """Computes a canonical SHA-256 digest of a judge submission directory (`A/` or `B/`)."""
    if os.path.islink(root) or not root.is_dir():
        raise IntegrityError(f"Submission directory missing or symlinked: {root}")
    entries: List[str] = []
    for cur_root, dirs, files in os.walk(root, followlinks=False):
        cur_path = Path(cur_root)
        dirs.sort()
        for d in dirs:
            if os.path.islink(cur_path / d):
                raise IntegrityError(f"Refusing symlink inside judge submission: {cur_path / d}")
        for fname in sorted(files):
            fp = cur_path / fname
            data = _read_regular_bytes(fp, max_bytes=MAX_SINGLE_FILE_BYTES, label="judge submission file")
            rel = fp.relative_to(root).as_posix()
            entries.append(f"{rel}\x00{hashlib.sha256(data).hexdigest()}")
    return hashlib.sha256(("\n".join(entries) + "\n").encode("utf-8")).hexdigest()


def init_campaign(
    out_dir: Path,
    *,
    seed: int,
    protocol_path: Optional[Path] = None,
    builder_model: str = "",
    force: bool = False,
) -> Dict[str, Any]:
    if os.path.islink(out_dir):
        raise BenchmarkError(f"Refusing symlinked campaign directory: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    campaign_file = out_dir / "campaign.json"
    judge_dir = out_dir / "judge"
    priv_dir = out_dir / ".private"
    if os.path.islink(campaign_file) or os.path.islink(judge_dir) or os.path.islink(priv_dir):
        raise BenchmarkError(f"Refusing symlinked campaign artifacts under {out_dir}")
    if (campaign_file.exists() or (priv_dir / "key.json").exists()) and not force:
        raise BenchmarkError(f"Campaign already initialized at {out_dir}; pass --force to overwrite.")

    protocol_sha = ""
    proto_str = ""
    if protocol_path is not None:
        raw = _read_regular_bytes(protocol_path, max_bytes=MAX_SINGLE_FILE_BYTES, label="protocol file")
        protocol_sha = hashlib.sha256(raw).hexdigest()
        proto_str = str(protocol_path)

    _verify_private_dir(priv_dir, create=True)
    with _exclusive_private_lock(priv_dir):
        key_file = priv_dir / "audit.key"
        audit_key = secrets.token_hex(32)
        _atomic_write_text_strict(key_file, audit_key + "\n", mode=0o600, private_parent=True)

        # Keep seed and builder_model strictly inside 0o600 .private/key.json so public campaign.json cannot unblind judges.
        private_key_obj = {
            "seed": int(seed),
            "builder_model": (builder_model or "").strip(),
            "pairs": {},
        }
        canon = _canonical_json(private_key_obj) + "\n"
        _atomic_write_text_strict(priv_dir / "key.json", canon, mode=0o600, private_parent=True)
        _atomic_write_text_strict(
            priv_dir / "key.seal",
            _hmac_hex(audit_key, canon.encode("utf-8")) + "\n",
            mode=0o600,
            private_parent=True,
        )

        # Public campaign metadata intentionally omits seed and builder_model.
        public_meta = {
            "created_at": _utc_now(),
            "protocol_path": proto_str,
            "protocol_sha256": protocol_sha,
        }
        _atomic_write_text_strict(campaign_file, json.dumps(public_meta, indent=2) + "\n", mode=0o644)
        judge_dir.mkdir(exist_ok=True)
    return {**public_meta, "seed": int(seed)}


def _copy_submission_sanitized(src: Path, dest_dir: Path) -> Tuple[int, int]:
    """
    Copies a single file (normalized to `submission<ext>`) or directory tree into `dest_dir`,
    stripping harness-identifying files and refusing symlinks/non-regular entries/oversized trees.
    """
    if os.path.islink(src):
        raise IntegrityError(f"Refusing symlinked submission source: {src}")
    if not src.exists():
        raise BenchmarkError(f"Submission source not found: {src}")

    dest_dir.mkdir(parents=True, exist_ok=True)
    st = os.lstat(src)
    if stat.S_ISREG(st.st_mode):
        data = _read_regular_bytes(src, max_bytes=MAX_SINGLE_FILE_BYTES, label="submission file")
        ext = src.suffix if re.fullmatch(r"\.[A-Za-z0-9_.-]{1,16}", src.suffix or "") else ""
        (dest_dir / f"submission{ext}").write_bytes(data)
        return 1, len(data)
    if not stat.S_ISDIR(st.st_mode):
        raise IntegrityError(f"Refusing non-regular submission source: {src}")

    file_count = 0
    total_bytes = 0
    for cur_root, dirs, files in os.walk(src, followlinks=False):
        cur_path = Path(cur_root)
        kept_dirs: List[str] = []
        for d in sorted(dirs):
            if d in STRIPPED_NAMES:
                continue
            dp = cur_path / d
            if os.path.islink(dp):
                raise IntegrityError(f"Refusing symlinked directory inside submission: {dp}")
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        rel_dir = cur_path.relative_to(src)
        target_dir = dest_dir / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)

        for fname in sorted(files):
            if fname in STRIPPED_NAMES:
                continue
            fp = cur_path / fname
            if os.path.islink(fp):
                raise IntegrityError(f"Refusing symlinked file inside submission: {fp}")
            data = _read_regular_bytes(fp, max_bytes=MAX_SINGLE_FILE_BYTES, label="submission file")
            file_count += 1
            total_bytes += len(data)
            if file_count > MAX_TREE_FILES:
                raise IntegrityError(f"Submission exceeds file count limit ({MAX_TREE_FILES}): {src}")
            if total_bytes > MAX_TREE_BYTES:
                raise IntegrityError(f"Submission exceeds total size limit ({MAX_TREE_BYTES} bytes): {src}")
            (target_dir / fname).write_bytes(data)

    if file_count == 0:
        raise IntegrityError(f"Submission contains zero inspectable files after stripping ledgers: {src}")
    return file_count, total_bytes


def scan_tree_for_leaks(
    root: Path,
    *,
    markers: Sequence[str],
    allowed: Iterable[str] = (),
) -> List[Dict[str, str]]:
    """Scans both relative file paths and raw bytes (case-insensitive) for unblinding markers."""
    allow_set = {a.strip().lower() for a in allowed if a and a.strip()}
    active = [m.strip().lower() for m in markers if m and m.strip() and m.strip().lower() not in allow_set]
    active_bytes = [(tok, tok.encode("utf-8")) for tok in active]
    hits: List[Dict[str, str]] = []

    for cur_root, dirs, files in os.walk(root, followlinks=False):
        cur_path = Path(cur_root)
        for d in sorted(dirs):
            dp = cur_path / d
            if os.path.islink(dp):
                raise IntegrityError(f"Refusing symlink in judge folder: {dp}")
            rel = dp.relative_to(root).as_posix().lower()
            for tok, _ in active_bytes:
                if tok in rel:
                    hits.append({"path": dp.relative_to(root).as_posix(), "marker": tok, "where": "path"})
        for fname in sorted(files):
            fp = cur_path / fname
            rel_orig = fp.relative_to(root).as_posix()
            rel_low = rel_orig.lower()
            for tok, _ in active_bytes:
                if tok in rel_low:
                    hits.append({"path": rel_orig, "marker": tok, "where": "path"})
            raw = _read_regular_bytes(fp, max_bytes=MAX_SINGLE_FILE_BYTES, label="judge file")
            low_bytes = raw.lower()
            for tok, tok_b in active_bytes:
                if tok_b in low_bytes:
                    hits.append({"path": rel_orig, "marker": tok, "where": "content"})
    return hits


def _load_verified_key_store(campaign_dir: Path) -> Tuple[str, Dict[str, Any], bool]:
    priv = campaign_dir / ".private"
    _verify_private_dir(priv, create=False)
    try:
        audit_key = _read_regular_bytes(priv / "audit.key", max_bytes=4096, label="audit.key").decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"Corrupt non-UTF-8 .private/audit.key: {exc}") from exc
    key_raw = _read_regular_bytes(priv / "key.json", max_bytes=MAX_SINGLE_FILE_BYTES, label="key.json")
    try:
        seal_raw = _read_regular_bytes(priv / "key.seal", max_bytes=4096, label="key.seal").decode("utf-8").strip()
    except (BenchmarkError, UnicodeDecodeError):
        seal_raw = ""
    expected_seal = _hmac_hex(audit_key, key_raw)
    seal_ok = bool(seal_raw) and _safe_compare(seal_raw, expected_seal)
    try:
        key_obj = json.loads(key_raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Corrupt .private/key.json: {exc}") from exc
    if not isinstance(key_obj, dict) or not isinstance(key_obj.get("pairs"), dict):
        raise IntegrityError("Malformed .private/key.json schema.")
    for tid in key_obj["pairs"].keys():
        if not isinstance(tid, str) or not TASK_ID_RE.fullmatch(tid):
            raise IntegrityError(f"Invalid task id in .private/key.json: {tid!r}")
    return audit_key, key_obj, seal_ok


def pair_task(
    campaign_dir: Path,
    *,
    task_id: str,
    off_src: Path,
    on_src: Path,
    builder_model: str = "",
    allow_markers: Sequence[str] = (),
    deny_markers: Sequence[str] = (),
    force: bool = False,
) -> Dict[str, Any]:
    if not TASK_ID_RE.fullmatch(task_id or ""):
        raise BenchmarkError(f"Invalid --task id {task_id!r}: must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$.")
    if os.path.islink(campaign_dir):
        raise BenchmarkError(f"Refusing symlinked campaign directory: {campaign_dir}")
    # Verify campaign.json exists and parses cleanly
    try:
        c_raw = _read_regular_bytes(campaign_dir / "campaign.json", max_bytes=MAX_SINGLE_FILE_BYTES, label="campaign.json")
        if not isinstance(json.loads(c_raw.decode("utf-8", errors="strict")), dict):
            raise IntegrityError("campaign.json must be a JSON object.")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Corrupt campaign.json: {exc}") from exc

    priv_dir = campaign_dir / ".private"
    judge_root = campaign_dir / "judge"
    if os.path.islink(judge_root):
        raise BenchmarkError(f"Refusing symlinked judge directory: {judge_root}")

    with _exclusive_private_lock(priv_dir):
        audit_key, key_obj, seal_ok = _load_verified_key_store(campaign_dir)
        if not seal_ok:
            raise IntegrityError("Refusing to pair into campaign with tampered or missing .private/key.seal.")
        if task_id in key_obj["pairs"] and not force:
            raise BenchmarkError(f"Task {task_id!r} already paired; pass --force to replace.")
        if "seed" not in key_obj or isinstance(key_obj["seed"], bool) or not isinstance(key_obj["seed"], int):
            raise IntegrityError("Missing or invalid integer seed in .private/key.json.")
        seed = int(key_obj["seed"])

        # Keyed HMAC slot polarity prevents unblinding even if a judge guesses the seed.
        polarity = int(_hmac_hex(audit_key, f"slot:{seed}:{task_id}".encode("utf-8"))[:2], 16)
        if polarity % 2 == 0:
            o1_map = {"A": "OFF", "B": "ON"}
            o2_map = {"A": "ON", "B": "OFF"}
        else:
            o1_map = {"A": "ON", "B": "OFF"}
            o2_map = {"A": "OFF", "B": "ON"}

        judge_root.mkdir(parents=True, exist_ok=True)
        markers = (*DEFAULT_LEAK_MARKERS, *deny_markers)
        order_meta: Dict[str, Dict[str, Any]] = {}

        with tempfile.TemporaryDirectory(prefix=f".staging-{task_id}-", dir=str(judge_root)) as stage_str:
            stage_dir = Path(stage_str)
            for order_name, mapping in (("o1", o1_map), ("o2", o2_map)):
                pair_dir = stage_dir / f"pair-{task_id}-{order_name}"
                pair_dir.mkdir(parents=True, exist_ok=True)
                for slot in ("A", "B"):
                    src = off_src if mapping[slot] == "OFF" else on_src
                    _copy_submission_sanitized(src, pair_dir / slot)
                leaks = scan_tree_for_leaks(pair_dir, markers=markers, allowed=allow_markers)
                if leaks:
                    sample = "; ".join(f"{h['path']} ({h['where']}: {h['marker']})" for h in leaks[:5])
                    raise IntegrityError(f"Leak scan failed for {task_id} ({order_name}): {sample}")

                sha_a = _hash_submission_tree(pair_dir / "A")
                sha_b = _hash_submission_tree(pair_dir / "B")
                token_payload = _canonical_json({
                    "mapping": mapping,
                    "order": order_name,
                    "seed": seed,
                    "sha256_A": sha_a,
                    "sha256_B": sha_b,
                    "task": task_id,
                }).encode("utf-8")
                order_sealed = _hmac_hex(audit_key, token_payload)[:16]
                order_meta[order_name] = {
                    "mapping": mapping,
                    "sealed": order_sealed,
                    "sha256_A": sha_a,
                    "sha256_B": sha_b,
                }
                ask_text = (
                    f"# Blind Evaluation Task `{task_id}` ({order_name})\n\n"
                    "Compare submission `A/` and submission `B/` strictly on defect prevention, test integrity, "
                    "correctness, and minimality. Do not inspect files outside this directory.\n\n"
                    "Write `verdict.json` in this directory with exact keys:\n"
                    "```json\n"
                    "{\n"
                    '  "winner": "A | B | tie",\n'
                    '  "why": "Concrete evidence citing file paths and defects observed",\n'
                    f'  "sealed": "{order_sealed}",\n'
                    '  "judge_model": "<your model display name>"\n'
                    "}\n"
                    "```\n"
                )
                (pair_dir / "ask.md").write_text(ask_text, encoding="utf-8")

            for order_name in ("o1", "o2"):
                dest = judge_root / f"pair-{task_id}-{order_name}"
                if os.path.islink(dest):
                    raise BenchmarkError(f"Refusing symlinked judge destination: {dest}")
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.move(str(stage_dir / f"pair-{task_id}-{order_name}"), str(dest))

        effective_builder = (builder_model or str(key_obj.get("builder_model") or "")).strip()
        record = {
            "o1": o1_map,
            "o2": o2_map,
            "sealed_o1": order_meta["o1"]["sealed"],
            "sealed_o2": order_meta["o2"]["sealed"],
            "digests": {
                "o1": {"A": order_meta["o1"]["sha256_A"], "B": order_meta["o1"]["sha256_B"]},
                "o2": {"A": order_meta["o2"]["sha256_A"], "B": order_meta["o2"]["sha256_B"]},
            },
            "builder_model": effective_builder,
            "allowed_markers": sorted({a.strip().lower() for a in allow_markers if a and a.strip()}),
            "paired_at": _utc_now(),
        }
        key_obj["pairs"][task_id] = record
        canon = _canonical_json(key_obj) + "\n"
        _atomic_write_text_strict(priv_dir / "key.json", canon, mode=0o600, private_parent=True)
        _atomic_write_text_strict(
            priv_dir / "key.seal",
            _hmac_hex(audit_key, canon.encode("utf-8")) + "\n",
            mode=0o600,
            private_parent=True,
        )
    return {
        "task_id": task_id,
        "sealed_o1": order_meta["o1"]["sealed"],
        "sealed_o2": order_meta["o2"]["sealed"],
        "o1_dir": str(judge_root / f"pair-{task_id}-o1"),
        "o2_dir": str(judge_root / f"pair-{task_id}-o2"),
    }


def _require_int_in(val: Any, allowed: Set[int], label: str, line_no: int) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or val not in allowed:
        raise IntegrityError(f"Ledger line {line_no}: {label} must be an integer in {sorted(allowed)}, got {val!r}")
    return val


def _require_nonneg_int(val: Any, label: str, line_no: int) -> int:
    if isinstance(val, bool) or not isinstance(val, int) or val < 0:
        raise IntegrityError(f"Ledger line {line_no}: {label} must be an integer >= 0, got {val!r}")
    return val


def score_ledger(ledger_path: Path) -> Dict[str, Any]:
    raw = _read_regular_bytes(ledger_path, max_bytes=MAX_SINGLE_FILE_BYTES, label="ledger JSONL")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"Corrupt non-UTF-8 ledger JSONL ({ledger_path}): {exc}") from exc
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise IntegrityError(f"Ledger has 0 rows: {ledger_path}")

    pairs: Dict[Tuple[str, str, str, str], Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for idx, line in enumerate(lines, start=1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"Ledger line {idx}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise IntegrityError(f"Ledger line {idx}: row must be a JSON object")
        missing = [k for k in REQUIRED_LEDGER_KEYS if k not in row]
        if missing:
            raise IntegrityError(f"Ledger line {idx}: missing keys {missing}")
        cond = row["condition"]
        if cond not in ("OFF", "ON"):
            raise IntegrityError(f"Ledger line {idx}: invalid condition {cond!r}")
        _require_int_in(row["tier"], {1, 2, 3}, "tier", idx)
        _require_int_in(row["acceptance_pass"], {0, 1}, "acceptance_pass", idx)
        _require_int_in(row["rule9_intact"], {0, 1}, "rule9_intact", idx)
        for int_key in ("stop_gate_strikes", "auditor_confirmed_defects", "user_corrections"):
            _require_nonneg_int(row[int_key], int_key, idx)
        for num_key in ("wall_clock_sec", "total_tokens"):
            val = row[num_key]
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(float(val)) or float(val) < 0.0:
                raise IntegrityError(f"Ledger line {idx}: {num_key} must be a finite number >= 0, got {val!r}")

        key = (str(row["task_id"]), str(row["repo"]), str(row["base_sha"]), str(row["model"]))
        if cond in pairs[key]:
            raise IntegrityError(f"Ledger line {idx}: duplicate {cond} row for {key}")
        pairs[key][cond] = row

    unpaired = [k for k, v in pairs.items() if set(v.keys()) != {"OFF", "ON"}]
    if unpaired:
        raise IntegrityError(f"Ledger has unpaired OFF/ON runs: {unpaired}")

    ordered = sorted(pairs.keys())
    for key in ordered:
        if pairs[key]["OFF"]["tier"] != pairs[key]["ON"]["tier"]:
            raise IntegrityError(
                f"Mismatched tier between OFF ({pairs[key]['OFF']['tier']}) and ON ({pairs[key]['ON']['tier']}) for {key}"
            )

    summary: Dict[str, Dict[str, Any]] = {}
    for cond in ("OFF", "ON"):
        rs = [pairs[k][cond] for k in ordered]
        summary[cond] = {
            "pairs": len(rs),
            "acceptance_pass": sum(int(r["acceptance_pass"]) for r in rs),
            "rule9_intact": sum(int(r["rule9_intact"]) for r in rs),
            "stop_gate_strikes": sum(int(r["stop_gate_strikes"]) for r in rs),
            "auditor_confirmed_defects": sum(int(r["auditor_confirmed_defects"]) for r in rs),
            "user_corrections": sum(int(r["user_corrections"]) for r in rs),
            "median_wall_clock_sec": round(float(statistics.median(float(r["wall_clock_sec"]) for r in rs)), 2),
            "median_total_tokens": round(float(statistics.median(float(r["total_tokens"]) for r in rs)), 2),
        }

    t12 = [k for k in ordered if pairs[k]["OFF"]["tier"] in (1, 2)]
    delta_pct: Optional[float] = None
    within_budget = True
    if t12:
        off_med = float(statistics.median(float(pairs[k]["OFF"]["total_tokens"]) for k in t12))
        on_med = float(statistics.median(float(pairs[k]["ON"]["total_tokens"]) for k in t12))
        if off_med > 0.0:
            delta_pct = round(((on_med - off_med) / off_med) * 100.0, 2)
            within_budget = delta_pct <= 25.0
        elif on_med == 0.0:
            delta_pct = 0.0
            within_budget = True
        else:
            delta_pct = None
            within_budget = False

    return {
        "ok": within_budget,
        "pairs": len(ordered),
        "conditions": summary,
        "tier12_pairs": len(t12),
        "tier12_token_delta_pct": delta_pct,
        "tier12_within_budget": within_budget,
    }


def score_campaign(
    campaign_dir: Path,
    *,
    builder_model_override: str = "",
    require_cross_model: bool = False,
) -> Dict[str, Any]:
    if os.path.islink(campaign_dir):
        raise BenchmarkError(f"Refusing symlinked campaign directory: {campaign_dir}")
    try:
        c_raw = _read_regular_bytes(campaign_dir / "campaign.json", max_bytes=MAX_SINGLE_FILE_BYTES, label="campaign.json")
        if not isinstance(json.loads(c_raw.decode("utf-8", errors="strict")), dict):
            raise IntegrityError("campaign.json must be a JSON object.")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"Corrupt campaign.json: {exc}") from exc

    _, key_obj, seal_valid = _load_verified_key_store(campaign_dir)
    if not seal_valid:
        return {
            "ok": False,
            "verdict": "not shown",
            "seal_valid": False,
            "total_pairs": len(key_obj.get("pairs", {})),
            "decisive": 0,
            "on_wins": 0,
            "off_wins": 0,
            "ties": 0,
            "order_flips": 0,
            "incomplete": 0,
            "unsealed_verdicts": 0,
            "verdict_leaks": 0,
            "submission_tampered": 0,
            "p_value": 1.0,
            "wilson_ci_95": None,
            "self_review": False,
            "self_review_pairs": [],
            "cautions": [],
            "reasons": ["key.seal is missing or invalid (tamper detected); verdict evaluation aborted"],
            "tasks": [],
        }

    pairs_map = key_obj.get("pairs", {})
    campaign_builder = str(key_obj.get("builder_model") or "").strip()
    judge_root = campaign_dir / "judge"

    on_wins = 0
    off_wins = 0
    ties = 0
    order_flips = 0
    incomplete = 0
    unsealed_verdicts = 0
    verdict_leaks = 0
    submission_tampered = 0
    self_review_pairs: List[str] = []
    missing_model_provenance: List[str] = []
    per_task: List[Dict[str, Any]] = []

    for task_id in sorted(pairs_map.keys()):
        entry = pairs_map[task_id]
        if not isinstance(entry, dict):
            raise IntegrityError(f"Malformed pair entry for {task_id!r} in .private/key.json.")
        private_builder = (builder_model_override or str(entry.get("builder_model") or "") or campaign_builder).strip()
        allowed_set = {str(a).strip().lower() for a in (entry.get("allowed_markers") or ()) if str(a).strip()}
        active_verdict_markers = tuple(
            m for m in DEFAULT_LEAK_MARKERS if m.lower() not in allowed_set
        ) + ALWAYS_FORBIDDEN_VERDICT_MARKERS

        mapped_picks: List[Optional[str]] = []
        judge_models: List[str] = []
        task_issues: List[str] = []

        for order_name in ("o1", "o2"):
            pair_dir = judge_root / f"pair-{task_id}-{order_name}"
            expected_sealed = str(entry.get(f"sealed_{order_name}") or entry.get("sealed") or "")

            # Re-verify submission digests to catch post-pairing tampering of judge/A or judge/B
            expected_digests = (entry.get("digests") or {}).get(order_name)
            if isinstance(expected_digests, dict):
                try:
                    cur_a = _hash_submission_tree(pair_dir / "A")
                    cur_b = _hash_submission_tree(pair_dir / "B")
                    if not (
                        _safe_compare(cur_a, str(expected_digests.get("A", "")))
                        and _safe_compare(cur_b, str(expected_digests.get("B", "")))
                    ):
                        submission_tampered += 1
                        task_issues.append(f"{order_name} submission files modified after pairing")
                except (BenchmarkError, IntegrityError) as exc:
                    submission_tampered += 1
                    task_issues.append(f"{order_name} submission tree tampered/missing: {exc}")

            vpath = pair_dir / "verdict.json"
            try:
                vraw = _read_regular_bytes(vpath, max_bytes=MAX_SINGLE_FILE_BYTES, label=f"{task_id} {order_name} verdict")
                vobj = json.loads(vraw.decode("utf-8", errors="strict"))
            except (BenchmarkError, IntegrityError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                mapped_picks.append(None)
                task_issues.append(f"{order_name} missing/corrupt: {exc}")
                continue
            if not isinstance(vobj, dict):
                mapped_picks.append(None)
                task_issues.append(f"{order_name} verdict is not a JSON object")
                continue

            raw_winner = vobj.get("winner")
            winner = raw_winner.strip() if isinstance(raw_winner, str) else ""
            if winner not in ("A", "B", "tie"):
                mapped_picks.append(None)
                task_issues.append(f"{order_name} invalid winner {raw_winner!r}")
                continue

            raw_seal = vobj.get("sealed")
            given_seal = raw_seal.strip() if isinstance(raw_seal, str) else ""
            if not expected_sealed or not _safe_compare(given_seal, expected_sealed):
                unsealed_verdicts += 1
                task_issues.append(f"{order_name} invalid or missing sealed token")

            raw_why = vobj.get("why")
            why_low = raw_why.lower() if isinstance(raw_why, str) else ""
            for marker in active_verdict_markers:
                if marker in why_low:
                    verdict_leaks += 1
                    task_issues.append(f"{order_name} verdict leaked marker {marker!r}")
                    break

            raw_jm = vobj.get("judge_model")
            j_model = raw_jm.strip() if isinstance(raw_jm, str) else ""
            if j_model:
                judge_models.append(j_model)

            order_map = entry.get(order_name)
            if winner == "tie":
                mapped_picks.append("tie")
            else:
                if not isinstance(order_map, dict) or order_map.get(winner) not in ("ON", "OFF"):
                    raise IntegrityError(f"Corrupt order mapping for {task_id} {order_name} in .private/key.json.")
                mapped_picks.append(str(order_map[winner]))

        if any(p is None for p in mapped_picks):
            incomplete += 1
            outcome = "incomplete"
        else:
            p1, p2 = mapped_picks[0], mapped_picks[1]
            if p1 == "ON" and p2 == "ON":
                on_wins += 1
                outcome = "ON"
            elif p1 == "OFF" and p2 == "OFF":
                off_wins += 1
                outcome = "OFF"
            elif p1 == "tie" and p2 == "tie":
                ties += 1
                outcome = "tie"
            else:
                order_flips += 1
                outcome = "order_flip"

        same_fam = any(is_same_model_family(private_builder, jm) for jm in judge_models)
        if same_fam:
            self_review_pairs.append(task_id)
        if not canonical_model_family(private_builder) or len(judge_models) < 2 or any(
            not canonical_model_family(jm) for jm in judge_models
        ):
            missing_model_provenance.append(task_id)

        per_task.append(
            {
                "task_id": task_id,
                "outcome": outcome,
                "judge_models": judge_models,
                "self_review": same_fam,
                "issues": task_issues,
            }
        )

    decisive = on_wins + off_wins
    p_value = exact_two_sided_sign_test(on_wins, decisive)
    ci = wilson_95_interval(on_wins, decisive)
    self_review = len(self_review_pairs) > 0

    reasons: List[str] = []
    cautions: List[str] = []
    if len(pairs_map) == 0:
        reasons.append("campaign has 0 paired tasks")
    if submission_tampered > 0:
        reasons.append(f"{submission_tampered} judge submission folder(s) modified or missing after pairing")
    if incomplete > 0:
        reasons.append(f"{incomplete} pair(s) missing or corrupt o1/o2 verdict.json")
    if unsealed_verdicts > 0:
        reasons.append(f"{unsealed_verdicts} verdict(s) missing or mismatched sealed token")
    if verdict_leaks > 0:
        reasons.append(f"{verdict_leaks} verdict(s) mentioned unblinding arm/harness markers")
    if decisive < 6:
        reasons.append(f"fewer than 6 decisive pairs ({decisive}); sign test cannot reach p < 0.05")
    if on_wins <= off_wins:
        reasons.append(f"ON wins ({on_wins}) do not exceed OFF wins ({off_wins})")
    if p_value >= 0.05:
        reasons.append(f"two-sided sign test p={p_value:.5f} >= 0.05")
    if self_review:
        cautions.append(
            f"self_review: judge model shares builder model family on {len(self_review_pairs)} pair(s) "
            f"({', '.join(self_review_pairs)}); cross-model-family verification is recommended"
        )
        if require_cross_model:
            reasons.append("self_review detected under --require-cross-model")
    if require_cross_model and missing_model_provenance:
        reasons.append(
            f"missing builder_model or judge_model provenance under --require-cross-model on "
            f"{', '.join(missing_model_provenance)}"
        )

    integrity_ok = (
        seal_valid
        and submission_tampered == 0
        and incomplete == 0
        and unsealed_verdicts == 0
        and verdict_leaks == 0
    )
    verdict = "ahead" if not reasons else "not shown"

    return {
        "ok": integrity_ok,
        "verdict": verdict,
        "seal_valid": seal_valid,
        "total_pairs": len(pairs_map),
        "decisive": decisive,
        "on_wins": on_wins,
        "off_wins": off_wins,
        "ties": ties,
        "order_flips": order_flips,
        "incomplete": incomplete,
        "unsealed_verdicts": unsealed_verdicts,
        "verdict_leaks": verdict_leaks,
        "submission_tampered": submission_tampered,
        "p_value": round(p_value, 6),
        "wilson_ci_95": list(ci) if ci is not None else None,
        "self_review": self_review,
        "self_review_pairs": self_review_pairs,
        "cautions": cautions,
        "reasons": reasons,
        "tasks": per_task,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmark_eval",
        description="Blinded A/B benchmark pair generator, leak scanner, HMAC seal, and statistical scorer.",
        allow_abbrev=False,
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_init = sub.add_parser("init", help="Initialize a blinded A/B benchmark campaign folder")
    p_init.add_argument("--out", required=True, help="Campaign output directory")
    p_init.add_argument("--seed", type=int, required=True, help="Deterministic integer RNG seed (stored privately)")
    p_init.add_argument("--protocol", help="Optional path to benchmark protocol file to hash")
    p_init.add_argument("--builder-model", default="", help="Private builder model name for self-review detection")
    p_init.add_argument("--force", action="store_true", help="Overwrite existing campaign and keys")
    p_init.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    p_pair = sub.add_parser("pair", help="Create mirrored blinded o1/o2 judge folders with leak scan and per-order HMAC tokens")
    p_pair.add_argument("--campaign", required=True, help="Initialized campaign directory")
    p_pair.add_argument("--task", required=True, help="Task identifier (e.g. BM-01)")
    p_pair.add_argument("--off", required=True, help="Condition A (Harness OFF) file or directory")
    p_pair.add_argument("--on", required=True, help="Condition B (Harness ON) file or directory")
    p_pair.add_argument("--builder-model", default="", help="Optional per-task builder model override (kept private)")
    p_pair.add_argument("--allow", action="append", default=[], help="Allowlisted marker word (repeatable)")
    p_pair.add_argument("--deny", action="append", default=[], help="Additional leak marker word (repeatable)")
    p_pair.add_argument("--force", action="store_true", help="Replace an existing paired task")
    p_pair.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")

    p_score = sub.add_parser("score", help="Score benchmark_runs.jsonl ledger and/or blinded campaign verdicts")
    p_score.add_argument("--ledger", help="Path to benchmark_runs.jsonl")
    p_score.add_argument("--campaign", help="Path to blinded benchmark campaign directory")
    p_score.add_argument("--builder-model", default="", help="Optional private builder model override for self-review check")
    p_score.add_argument("--require-ahead", action="store_true", help="Exit 1 unless blinded campaign verdict is 'ahead'")
    p_score.add_argument("--require-cross-model", action="store_true", help="Withhold 'ahead' on self_review or missing model provenance")
    p_score.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.action == "init":
            meta = init_campaign(
                Path(args.out),
                seed=args.seed,
                protocol_path=Path(args.protocol) if args.protocol else None,
                builder_model=args.builder_model,
                force=bool(args.force),
            )
            if args.as_json:
                print(json.dumps(meta, indent=2))
            else:
                print(f"[BENCHMARK:INIT] Campaign initialized at {args.out}")
            return 0

        if args.action == "pair":
            res = pair_task(
                Path(args.campaign),
                task_id=args.task,
                off_src=Path(args.off),
                on_src=Path(args.on),
                builder_model=args.builder_model,
                allow_markers=args.allow,
                deny_markers=args.deny,
                force=bool(args.force),
            )
            if args.as_json:
                print(json.dumps(res, indent=2))
            else:
                print(
                    f"[BENCHMARK:PAIR] Paired {res['task_id']} "
                    f"(o1={res['sealed_o1']}, o2={res['sealed_o2']}) -> {res['o1_dir']}, {res['o2_dir']}"
                )
            return 0

        if args.action == "score":
            if not args.ledger and not args.campaign:
                raise BenchmarkError("Specify at least one of --ledger <jsonl> or --campaign <dir>.")
            out: Dict[str, Any] = {}
            failed = False
            if args.ledger:
                l_res = score_ledger(Path(args.ledger))
                out["ledger"] = l_res
                if not l_res["ok"]:
                    failed = True
            if args.campaign:
                c_res = score_campaign(
                    Path(args.campaign),
                    builder_model_override=args.builder_model,
                    require_cross_model=bool(args.require_cross_model),
                )
                out["campaign"] = c_res
                if not c_res["ok"]:
                    failed = True
                if args.require_ahead and c_res["verdict"] != "ahead":
                    failed = True
            if args.as_json:
                print(json.dumps(out, indent=2))
            else:
                if "ledger" in out:
                    lr = out["ledger"]
                    for cond in ("OFF", "ON"):
                        c = lr["conditions"][cond]
                        print(
                            f"{cond:3s} | pairs={c['pairs']:2d} | pass={c['acceptance_pass']}/{c['pairs']}"
                            f" | rule9={c['rule9_intact']}/{c['pairs']} | strikes={c['stop_gate_strikes']}"
                            f" | defects={c['auditor_confirmed_defects']} | corrections={c['user_corrections']}"
                            f" | med_sec={c['median_wall_clock_sec']}s | med_tokens={c['median_total_tokens']}"
                        )
                    print(
                        f"Tier 1/2 token delta: {lr['tier12_token_delta_pct']}% "
                        f"(within <= +25.0% budget: {lr['tier12_within_budget']})"
                    )
                if "campaign" in out:
                    cr = out["campaign"]
                    print(
                        f"[BENCHMARK:SCORE] verdict={cr['verdict']} | decisive={cr['decisive']} "
                        f"(ON={cr['on_wins']}, OFF={cr['off_wins']}, ties={cr['ties']}, flips={cr['order_flips']}) "
                        f"| p={cr['p_value']} | wilson95={cr['wilson_ci_95']} | self_review={cr['self_review']}"
                    )
                    for caution in cr["cautions"]:
                        print(f"  [CAUTION] {caution}")
                    for reason in cr["reasons"]:
                        print(f"  [REASON]  {reason}")
            return 1 if failed else 0
    except IntegrityError as exc:
        if getattr(args, "as_json", False):
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"[INTEGRITY ERROR] {exc}", file=sys.stderr)
        return 1
    except BenchmarkError as exc:
        if getattr(args, "as_json", False):
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"[ERROR] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
