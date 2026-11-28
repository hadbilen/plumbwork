#!/usr/bin/env python3
"""Hermetic tests for ADR-0018 Feature 1: guard/property_ledger.py, CLI ledger-* actions, and verify_invariants --property-ledger."""

from __future__ import annotations

import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401  # must precede repository imports per ADR-0010

from guard.property_ledger import LedgerError, PropertyLedger  # noqa: E402


def _run_guard(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "guard.py"), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def _run_verify_invariants(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_invariants.py"), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


class TestAdr0018PropertyLedger(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="plumbwork_adr0018_ledger_")
        self.root = Path(self._td.name)
        (self.root / "src").mkdir()
        self.src_file = self.root / "src" / "calc.py"
        self.src_file.write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
        self.check_script = self.root / "check_calc.py"
        self.check_script.write_text(
            "import sys\n"
            "from src.calc import add\n"
            "if add(2, 3) != 5:\n"
            "    print('FAIL add-sums-inputs: expected 5')\n"
            "    sys.exit(1)\n"
            "print('PASS add-sums-inputs')\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_full_state_machine_unchecked_unproven_holds_stale_broken_waived(self) -> None:
        ledger = PropertyLedger(self.root)
        cmd = f"{shlex.quote(sys.executable)} -B check_calc.py"

        # 1. Add -> unchecked; sync on unchecked must be refused
        row = ledger.add_row(
            row_id="add-sums-inputs",
            kind="invariant",
            prop="Addition returns the exact mathematical sum of two integers",
            covers_raw="src/calc.py",
            command=cmd,
            level="sampled",
        )
        initial_hash = row["covers_hash"]
        self.assertEqual(row["status"], "unchecked")
        st = ledger.status_report()
        self.assertFalse(st["ok"])
        self.assertEqual(st["rows"][0]["state"], "unchecked")
        ok_un, msg_un, _ = ledger.sync_row(row_id="add-sums-inputs", note="Cannot sync before run")
        self.assertFalse(ok_un)
        self.assertIn("unchecked", msg_un.lower())

        # File permissions must be 0644 (git-trackable, not 0600) on POSIX
        if os.name != "nt":
            mode = stat.S_IMODE(ledger.ledger_path.stat().st_mode)
            self.assertEqual(mode, 0o644)

        # 2. Run passing check without verify/red/<id>.txt -> unproven
        outcomes = ledger.run_rows(row_id="add-sums-inputs")
        self.assertEqual(len(outcomes), 1)
        self.assertTrue(outcomes[0].passed)
        self.assertEqual(outcomes[0].state, "unproven")
        self.assertEqual(ledger.status_report()["rows"][0]["state"], "unproven")

        # Sync without red proof must be refused
        ok_sync, msg_sync, _ = ledger.sync_row(row_id="add-sums-inputs", note="Attempt sync without red proof")
        self.assertFalse(ok_sync)
        self.assertIn("unproven", msg_sync.lower())

        # 3. Write red proof without FAIL line -> still unproven
        red_dir = self.root / "verify" / "red"
        red_dir.mkdir(parents=True, exist_ok=True)
        red_file = red_dir / "add-sums-inputs.txt"
        red_file.write_text("something failed without marker\n", encoding="utf-8")
        self.assertEqual(ledger.status_report()["rows"][0]["state"], "unproven")

        # 4. Write valid red proof (`FAIL <reason>`), then sync -> holds
        red_file.write_text("FAIL add-sums-inputs: expected 5 got 4\n", encoding="utf-8")
        self.assertEqual(ledger.status_report()["rows"][0]["state"], "unchecked")
        ok_sync, _, ev = ledger.sync_row(row_id="add-sums-inputs", note="Confirmed planted defect produces FAIL")
        self.assertTrue(ok_sync)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.state, "holds")
        self.assertTrue(ledger.status_report()["ok"])

        # Re-running an already holding unchanged row preserves holds
        re_outcomes = ledger.run_rows(row_id="add-sums-inputs")
        self.assertTrue(re_outcomes[0].passed)
        self.assertEqual(re_outcomes[0].state, "holds")

        # 5. Mutate covered code -> stale immediately; sync before re-run refused
        self.src_file.write_text("def add(a: int, b: int) -> int:\n    return a + b + 0\n", encoding="utf-8")
        self.assertEqual(ledger.status_report()["rows"][0]["state"], "stale")
        ok_stale_sync, msg_stale, _ = ledger.sync_row(row_id="add-sums-inputs", note="Try syncing stale code")
        self.assertFalse(ok_stale_sync)
        self.assertIn("re-run", msg_stale.lower())

        # 6. Plant real bug -> run -> broken; sync on broken MUST be refused even with valid red proof
        self.src_file.write_text("def add(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8")
        bad_outcomes = ledger.run_rows(row_id="add-sums-inputs")
        self.assertFalse(bad_outcomes[0].passed)
        self.assertEqual(bad_outcomes[0].state, "broken")
        ok_broken_sync, msg_broken, _ = ledger.sync_row(row_id="add-sums-inputs", note="Must refuse broken row")
        self.assertFalse(ok_broken_sync)
        self.assertIn("broken", msg_broken.lower())

        # 7. Evolve to DISTINCT passing code (different hash from initial_hash!), re-run, sync -> covers_hash advances!
        self.src_file.write_text("def add(a: int, b: int) -> int:\n    total = a + b\n    return total\n", encoding="utf-8")
        self.assertTrue(ledger.run_rows(row_id="add-sums-inputs")[0].passed)
        ok_resync, _, ev_resync = ledger.sync_row(row_id="add-sums-inputs", note="Synced refactored passing code")
        self.assertTrue(ok_resync)
        self.assertIsNotNone(ev_resync)
        self.assertEqual(ev_resync.state, "holds")
        self.assertNotEqual(ev_resync.covers_hash, initial_hash)
        self.assertEqual(ev_resync.covers_hash, ev_resync.current_hash)
        self.assertTrue(ledger.status_report()["ok"])

        # 8. Waive a non-logic layout file -> waived even after content edits, stale if deleted
        css_file = self.root / "src" / "layout.css"
        css_file.write_text("body { margin: 0; }\n", encoding="utf-8")
        waived = ledger.waive_paths(covers_raw="src/layout.css", why="Pure CSS spacing rules with no state logic")
        self.assertEqual(len(waived), 1)
        self.assertTrue(ledger.status_report()["ok"])
        self.assertEqual(ledger.status_report(file_filter="src/layout.css")["rows"][0]["state"], "waived")
        css_file.write_text("body { margin: 8px; }\n", encoding="utf-8")
        self.assertTrue(ledger.status_report()["ok"])
        css_file.unlink()
        self.assertFalse(ledger.status_report()["ok"])
        self.assertEqual(ledger.status_report(file_filter="src/layout.css")["rows"][0]["state"], "stale")

    def test_security_blocks_shell_operators_interpreters_traversal_symlinks_and_fifo(self) -> None:
        ledger = PropertyLedger(self.root)
        # Shell operators, shell interpreters, and Windows batch files rejected by default
        for bad_cmd in (
            "python3 check_calc.py; echo pwn",
            "python3 check_calc.py && echo pwn",
            "python3 check_calc.py | cat",
            "python3 check_calc.py &",
            "python3 $(echo check_calc.py)",
            "python3 check_calc.py > /tmp/out",
            "bash -c 'echo ok'",
            "/bin/sh -c 'echo ok'",
            "env python3 check_calc.py",
            "powershell -Command Get-Date",
            "run_checks.bat",
        ):
            with self.subTest(bad_cmd=bad_cmd):
                with self.assertRaises(LedgerError):
                    ledger.add_row(
                        row_id="safe-check",
                        kind="invariant",
                        prop="Command injection must be rejected by default",
                        covers_raw="src/calc.py",
                        command=bad_cmd,
                        level="sampled",
                    )

        # Path traversal and directories rejected
        with self.assertRaises(LedgerError):
            ledger.add_row(
                row_id="escape-check",
                kind="invariant",
                prop="Parent traversal must be rejected",
                covers_raw="../outside.py",
                command=f"{shlex.quote(sys.executable)} -B check_calc.py",
                level="sampled",
            )
        with self.assertRaises(LedgerError):
            ledger.add_row(
                row_id="dir-check",
                kind="invariant",
                prop="Directories must not be accepted as regular covered files",
                covers_raw="src",
                command=f"{shlex.quote(sys.executable)} -B check_calc.py",
                level="sampled",
            )

        # Tampered `red` path outside verify/red/ or pointing to another row's red file is rejected
        ledger.add_row(
            row_id="red-jail",
            kind="invariant",
            prop="Red proof path must strictly match verify/red/<id>.txt",
            covers_raw="src/calc.py",
            command=f"{shlex.quote(sys.executable)} -B check_calc.py",
            level="sampled",
        )
        ok_bad_red, reason_bad = ledger.check_red_proof("red-jail", "src/calc.py")
        self.assertFalse(ok_bad_red)
        self.assertIn("verify/red/red-jail.txt", reason_bad)
        ok_other_red, _ = ledger.check_red_proof("red-jail", "verify/red/other.txt")
        self.assertFalse(ok_other_red)

        # Symlinked covered file, symlinked red proof, symlinked verify/, and POSIX FIFO rejected without hanging
        if hasattr(os, "symlink"):
            outside = self.root.parent / f"{self.root.name}_outside.py"
            outside.write_text("FAIL stolen: 1\n", encoding="utf-8")
            try:
                link_src = self.root / "src" / "linked.py"
                try:
                    os.symlink(outside, link_src)
                    symlink_supported = True
                except (OSError, NotImplementedError):
                    symlink_supported = False
                if symlink_supported:
                    with self.assertRaises(LedgerError):
                        ledger.add_row(
                            row_id="link-check",
                            kind="invariant",
                            prop="Symlinked source file must be rejected",
                            covers_raw="src/linked.py",
                            command=f"{shlex.quote(sys.executable)} -B check_calc.py",
                            level="sampled",
                        )
                    red_dir = self.root / "verify" / "red"
                    red_dir.mkdir(parents=True, exist_ok=True)
                    os.symlink(outside, red_dir / "red-jail.txt")
                    ok_sym_red, sym_reason = ledger.check_red_proof("red-jail")
                    self.assertFalse(ok_sym_red)
                    self.assertIn("symlink", sym_reason.lower())

                    sym_root = self.root / "sym_ws"
                    sym_root.mkdir()
                    real_v = self.root / "real_v"
                    real_v.mkdir()
                    os.symlink(real_v, sym_root / "verify")
                    with self.assertRaises(LedgerError):
                        PropertyLedger(sym_root).exists()
            finally:
                outside.unlink(missing_ok=True)

        if hasattr(os, "mkfifo"):
            fifo_path = self.root / "src" / "pipe.py"
            os.mkfifo(fifo_path)
            with self.assertRaises(LedgerError):
                ledger.add_row(
                    row_id="fifo-check",
                    kind="invariant",
                    prop="Named pipes must be rejected without blocking",
                    covers_raw="src/pipe.py",
                    command=f"{shlex.quote(sys.executable)} -B check_calc.py",
                    level="sampled",
                )

    def test_run_rows_waived_skip_timeout_missing_exe_allow_shell_and_zero_runnable(self) -> None:
        ledger = PropertyLedger(self.root)
        css_file = self.root / "src" / "style.css"
        css_file.write_text("body{}\n", encoding="utf-8")
        waived = ledger.waive_paths(covers_raw="src/style.css", why="Pure styling file with no state logic")
        waived_id = waived[0]["id"]

        # Running a ledger with only waived rows (or targeting a waived row directly) must raise LedgerError
        with self.assertRaises(LedgerError):
            ledger.run_rows()
        with self.assertRaises(LedgerError):
            ledger.run_rows(row_id=waived_id)

        # Full-ledger run skips waived row cleanly and runs runnable rows
        ledger.add_row(
            row_id="fast-pass",
            kind="invariant",
            prop="Fast check passes while waived sibling is skipped",
            covers_raw="src/calc.py",
            command=f"{shlex.quote(sys.executable)} -B check_calc.py",
            level="sampled",
        )
        outs = ledger.run_rows()
        self.assertEqual([o.id for o in outs], ["fast-pass"])
        self.assertTrue(outs[0].passed)

        # Timeout enforcement -> rc=124, timed_out=True, state=broken
        (self.root / "sleep_check.py").write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
        ledger.add_row(
            row_id="slow-timeout",
            kind="liveness",
            prop="Hanging command must terminate cleanly on timeout",
            covers_raw="src/calc.py",
            command=f"{shlex.quote(sys.executable)} sleep_check.py",
            level="bounded",
        )
        t_outs = ledger.run_rows(row_id="slow-timeout", timeout=1)
        self.assertFalse(t_outs[0].passed)
        self.assertTrue(t_outs[0].timed_out)
        self.assertEqual(t_outs[0].returncode, 124)
        self.assertEqual(t_outs[0].state, "broken")

        # Missing executable -> rc=127, state=broken
        ledger.add_row(
            row_id="missing-bin",
            kind="state",
            prop="Missing executable fails cleanly as broken with rc 127",
            covers_raw="src/calc.py",
            command="nonexistent_binary_adr0018_xyz --check",
            level="sampled",
        )
        m_outs = ledger.run_rows(row_id="missing-bin")
        self.assertFalse(m_outs[0].passed)
        self.assertEqual(m_outs[0].returncode, 127)
        self.assertEqual(m_outs[0].state, "broken")

        # allow_shell=True on add_row is STILL blocked on run_rows(allow_shell=False) and runs with allow_shell=True
        ledger.add_row(
            row_id="shell-opt",
            kind="precondition",
            prop="Shell pipeline requires explicit allow_shell at run time too",
            covers_raw="src/calc.py",
            command=f'"{sys.executable}" -B check_calc.py && "{sys.executable}" -c "print(1)"',
            level="sampled",
            allow_shell=True,
        )
        with self.assertRaises(LedgerError):
            ledger.run_rows(row_id="shell-opt", allow_shell=False)
        sh_outs = ledger.run_rows(row_id="shell-opt", allow_shell=True)
        self.assertTrue(sh_outs[0].passed)

    def test_cli_ledger_actions_and_standalone_verify_invariants_without_git(self) -> None:
        # Missing ledger -> verify_invariants --property-ledger exits 2; ledger-status --json exits 2 with JSON stdout
        r_missing = _run_verify_invariants("--property-ledger", "--path", str(self.root), cwd=self.root)
        self.assertEqual(r_missing.returncode, 2, r_missing.stdout + r_missing.stderr)

        r_st_missing = _run_guard("test-boundary", "ledger-status", "--dir", str(self.root), "--json", cwd=self.root)
        self.assertEqual(r_st_missing.returncode, 2)
        self.assertFalse(json.loads(r_st_missing.stdout)["ok"])

        # ledger-status --allow-missing exits 0
        r_allow = _run_guard("test-boundary", "ledger-status", "--dir", str(self.root), "--allow-missing", "--json", cwd=self.root)
        self.assertEqual(r_allow.returncode, 0, r_allow.stdout + r_allow.stderr)
        self.assertTrue(json.loads(r_allow.stdout)["missing"])

        # Add -> Run -> Red proof -> Sync -> Status + Waive + --file filter via CLI
        r_add = _run_guard(
            "test-boundary",
            "ledger-add",
            "--dir",
            str(self.root),
            "--id",
            "calc-sum",
            "--kind",
            "postcondition",
            "--property",
            "add(a, b) returns the exact integer sum for inputs",
            "--covers",
            "src/calc.py",
            "--cmd",
            f"{shlex.quote(sys.executable)} -B check_calc.py",
            "--level",
            "sampled",
            "--json",
            cwd=self.root,
        )
        self.assertEqual(r_add.returncode, 0, r_add.stdout + r_add.stderr)

        # Uncovered file filter exits 1
        r_uncov = _run_guard("test-boundary", "ledger-status", "--dir", str(self.root), "--file", "src/other.py", cwd=self.root)
        self.assertEqual(r_uncov.returncode, 1)
        self.assertIn("NO RULE", r_uncov.stdout)

        # Blocked sync before run exits 1
        r_bad_sync = _run_guard(
            "test-boundary", "ledger-sync", "--dir", str(self.root), "--id", "calc-sum", "--note", "Too early sync", cwd=self.root
        )
        self.assertEqual(r_bad_sync.returncode, 1)

        # CLI ledger-waive
        css = self.root / "src" / "theme.css"
        css.write_text("a{color:red}\n", encoding="utf-8")
        r_waive = _run_guard(
            "test-boundary", "ledger-waive", "--dir", str(self.root), "--covers", "src/theme.css", "--why", "Static CSS theme tokens only", cwd=self.root
        )
        self.assertEqual(r_waive.returncode, 0, r_waive.stdout + r_waive.stderr)

        r_run = _run_guard("test-boundary", "ledger-run", "--dir", str(self.root), "--id", "calc-sum", "--json", cwd=self.root)
        self.assertEqual(r_run.returncode, 0, r_run.stdout + r_run.stderr)
        self.assertEqual(json.loads(r_run.stdout)[0]["state"], "unproven")

        red_dir = self.root / "verify" / "red"
        red_dir.mkdir(parents=True, exist_ok=True)
        (red_dir / "calc-sum.txt").write_text("FAIL calc-sum: planted bug returned a - b\n", encoding="utf-8")

        r_sync = _run_guard(
            "test-boundary",
            "ledger-sync",
            "--dir",
            str(self.root),
            "--id",
            "calc-sum",
            "--note",
            "Verified red proof on planted subtraction bug",
            "--json",
            cwd=self.root,
        )
        self.assertEqual(r_sync.returncode, 0, r_sync.stdout + r_sync.stderr)

        # Standalone verify_invariants --property-ledger passes AND does NOT falsely claim static/supply-chain scans passed!
        r_inv_ok = _run_verify_invariants("--property-ledger", "--path", str(self.root), cwd=self.root)
        self.assertEqual(r_inv_ok.returncode, 0, r_inv_ok.stdout + r_inv_ok.stderr)
        self.assertIn("holds=1", r_inv_ok.stdout)
        self.assertNotIn("Static scan clean", r_inv_ok.stdout)
        self.assertIn("skipped in --property-ledger-only mode", r_inv_ok.stdout)

        # Status and verify_invariants NEVER execute row commands (and exit 0 cleanly)
        marker = self.root / "should_not_exist.txt"
        ledger = PropertyLedger(self.root)
        rows = ledger.read_rows()
        rows[0]["command"] = f"{sys.executable} -c \"open('should_not_exist.txt','w').write('x')\""
        ledger.write_rows(rows)
        r_noexec_1 = _run_guard("test-boundary", "ledger-status", "--dir", str(self.root), cwd=self.root)
        r_noexec_2 = _run_verify_invariants("--property-ledger", "--path", str(self.root), cwd=self.root)
        self.assertEqual(r_noexec_1.returncode, 0)
        self.assertEqual(r_noexec_2.returncode, 0)
        self.assertFalse(marker.exists(), "status / verify_invariants must never execute ledger commands")

        # Empty (header-only) ledger -> exit 1; corrupt non-UTF-8 ledger -> exit 2 (with JSON on CLI)
        ledger.write_rows([])
        r_empty = _run_verify_invariants("--property-ledger", "--path", str(self.root), cwd=self.root)
        self.assertEqual(r_empty.returncode, 1)

        ledger.ledger_path.write_bytes(b"\xff\xfe\x00invalid-utf8")
        r_corrupt_inv = _run_verify_invariants("--property-ledger", "--path", str(self.root), cwd=self.root)
        self.assertEqual(r_corrupt_inv.returncode, 2)
        r_corrupt_cli = _run_guard("test-boundary", "ledger-status", "--dir", str(self.root), "--json", cwd=self.root)
        self.assertEqual(r_corrupt_cli.returncode, 2)
        self.assertFalse(json.loads(r_corrupt_cli.stdout)["ok"])


if __name__ == "__main__":
    unittest.main()
