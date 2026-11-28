#!/usr/bin/env python3
"""Hermetic tests for ADR-0018 Feature 3 (scripts/benchmark_eval.py) and Feature 4 (100x-engineer-skill release tracking & MIT notices)."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
for _p in (str(TESTS_DIR), str(REPO_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hermetic  # noqa: E402, F401  # must precede repository imports per ADR-0010

import guard.plugins as guard_plugins  # noqa: E402
import guard.upstream as guard_upstream  # noqa: E402
import scripts.benchmark_eval as bench  # noqa: E402


def _write_verdict(pair_dir: Path, *, winner: str, sealed: str, judge_model: str | None, why: str = "Clean diff") -> None:
    payload = {"winner": winner, "why": why, "sealed": sealed}
    if judge_model is not None:
        payload["judge_model"] = judge_model
    (pair_dir / "verdict.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class TestAdr0018BenchmarkEval(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="plumbwork_adr0018_bench_")
        self.root = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_multi_pair_per_order_tokens_blinding_order_flips_sign_test_and_self_review(self) -> None:
        camp = self.root / "camp"
        bench.init_campaign(
            camp,
            seed=42,
            protocol_path=REPO_ROOT / "docs" / "benchmark-protocol.md",
            builder_model="Gemini 4 Neon (XHigh)",
        )
        # Public campaign.json must NEVER leak seed or builder_model; .private/ stays 0o700 and files 0o600
        pub_meta = json.loads((camp / "campaign.json").read_text(encoding="utf-8"))
        self.assertNotIn("seed", pub_meta)
        self.assertNotIn("builder_model", pub_meta)
        self.assertFalse((camp / "judge" / "key.json").exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE((camp / ".private").stat().st_mode), 0o700)
            for fn in ("audit.key", "key.json", "key.seal"):
                self.assertEqual(stat.S_IMODE((camp / ".private" / fn).stat().st_mode), 0o600)

        # Pair 6 clean tasks; verify single-file normalization, mirrored o1/o2 content bytes, and distinct per-order tokens
        o1_first_arms = set()
        for idx in range(1, 7):
            off_f = self.root / f"bm-0{idx}-off.diff"
            on_f = self.root / f"bm-0{idx}-on.diff"
            off_bytes = f"diff --git a/app.py b/app.py\n-return {idx}\n+return {idx}\n".encode("utf-8")
            on_bytes = f"diff --git a/app.py b/app.py\n-return {idx}\n+return {idx + 1}\n".encode("utf-8")
            off_f.write_bytes(off_bytes)
            on_f.write_bytes(on_bytes)
            res = bench.pair_task(camp, task_id=f"BM-0{idx}", off_src=off_f, on_src=on_f)
            self.assertNotEqual(res["sealed_o1"], res["sealed_o2"])

            key_obj = json.loads((camp / ".private" / "key.json").read_text(encoding="utf-8"))
            entry = key_obj["pairs"][f"BM-0{idx}"]
            self.assertNotEqual(entry["o1"]["A"], entry["o2"]["A"])
            o1_first_arms.add(entry["o1"]["A"])

            o1_dir = Path(res["o1_dir"])
            o2_dir = Path(res["o2_dir"])
            self.assertFalse((o1_dir / "A" / off_f.name).exists())
            expected_o1_a = on_bytes if entry["o1"]["A"] == "ON" else off_bytes
            expected_o1_b = off_bytes if entry["o1"]["A"] == "ON" else on_bytes
            self.assertEqual((o1_dir / "A" / "submission.diff").read_bytes(), expected_o1_a)
            self.assertEqual((o1_dir / "B" / "submission.diff").read_bytes(), expected_o1_b)
            self.assertEqual((o2_dir / "A" / "submission.diff").read_bytes(), expected_o1_b)
            self.assertEqual((o2_dir / "B" / "submission.diff").read_bytes(), expected_o1_a)

            ask_o1 = (o1_dir / "ask.md").read_text(encoding="utf-8")
            ask_o2 = (o2_dir / "ask.md").read_text(encoding="utf-8")
            self.assertIn(res["sealed_o1"], ask_o1)
            self.assertIn(res["sealed_o2"], ask_o2)
            self.assertNotIn("Gemini 4 Neon", ask_o1)

        key_obj = json.loads((camp / ".private" / "key.json").read_text(encoding="utf-8"))

        # Cast 6/6 OFF wins first -> p = 0.03125, MUST be "not shown" (never "ahead" on regression!)
        for idx in range(1, 7):
            tid = f"BM-0{idx}"
            entry = key_obj["pairs"][tid]
            for order in ("o1", "o2"):
                off_slot = "A" if entry[order]["A"] == "OFF" else "B"
                _write_verdict(
                    camp / "judge" / f"pair-{tid}-{order}",
                    winner=off_slot,
                    sealed=entry[f"sealed_{order}"],
                    judge_model="Claude Opus 5.5 (High)",
                )
        s_off = bench.score_campaign(camp, require_cross_model=True)
        self.assertTrue(s_off["ok"])
        self.assertEqual(s_off["off_wins"], 6)
        self.assertAlmostEqual(s_off["p_value"], 0.03125, places=6)
        self.assertEqual(s_off["verdict"], "not shown")

        # Now cast 6/6 consistent ON wins with distinct judge family -> p = 0.03125, exact Wilson CI [0.6097, 1.0], "ahead"
        for idx in range(1, 7):
            tid = f"BM-0{idx}"
            entry = key_obj["pairs"][tid]
            for order in ("o1", "o2"):
                on_slot = "A" if entry[order]["A"] == "ON" else "B"
                _write_verdict(
                    camp / "judge" / f"pair-{tid}-{order}",
                    winner=on_slot,
                    sealed=entry[f"sealed_{order}"],
                    judge_model="Claude Opus 5.5 (High)",
                )

        s_ok = bench.score_campaign(camp, require_cross_model=True)
        self.assertTrue(s_ok["ok"], s_ok)
        self.assertEqual(s_ok["verdict"], "ahead")
        self.assertEqual(s_ok["decisive"], 6)
        self.assertEqual(s_ok["on_wins"], 6)
        self.assertAlmostEqual(s_ok["p_value"], 0.03125, places=6)
        self.assertEqual(s_ok["wilson_ci_95"], [0.6097, 1.0])
        self.assertFalse(s_ok["self_review"])

        # Missing/blank judge_model under --require-cross-model MUST fail closed ("not shown")
        bm1 = key_obj["pairs"]["BM-01"]
        on_bm1_o1 = "A" if bm1["o1"]["A"] == "ON" else "B"
        _write_verdict(camp / "judge" / "pair-BM-01-o1", winner=on_bm1_o1, sealed=bm1["sealed_o1"], judge_model="")
        s_missing_jm = bench.score_campaign(camp, require_cross_model=True)
        self.assertEqual(s_missing_jm["verdict"], "not shown")
        self.assertTrue(any("provenance" in r for r in s_missing_jm["reasons"]))

        # Same-family judge ("Gemini 4 Carbon (High)") flags self_review
        _write_verdict(
            camp / "judge" / "pair-BM-01-o1",
            winner=on_bm1_o1,
            sealed=bm1["sealed_o1"],
            judge_model="Gemini 4 Carbon (High)",
        )
        s_self = bench.score_campaign(camp, require_cross_model=False)
        self.assertTrue(s_self["self_review"])
        self.assertEqual(s_self["self_review_pairs"], ["BM-01"])
        self.assertEqual(s_self["verdict"], "ahead")
        self.assertEqual(bench.score_campaign(camp, require_cross_model=True)["verdict"], "not shown")

        # Cross-order replay (o1 token placed into o2 verdict) and non-ASCII sealed must fail cleanly without TypeError
        _write_verdict(
            camp / "judge" / "pair-BM-01-o1",
            winner=on_bm1_o1,
            sealed="tökén-non-ascii",
            judge_model="Claude Opus 5.5 (High)",
        )
        s_nonascii = bench.score_campaign(camp)
        self.assertFalse(s_nonascii["ok"])
        self.assertEqual(s_nonascii["unsealed_verdicts"], 1)

        # Restore BM-01-o1, then turn BM-06 into an order flip (o1=ON, o2=tie) -> decisive=5 -> p=0.0625 -> "not shown"
        _write_verdict(
            camp / "judge" / "pair-BM-01-o1",
            winner=on_bm1_o1,
            sealed=bm1["sealed_o1"],
            judge_model="Claude Opus 5.5 (High)",
        )
        _write_verdict(
            camp / "judge" / "pair-BM-06-o2",
            winner="tie",
            sealed=key_obj["pairs"]["BM-06"]["sealed_o2"],
            judge_model="Claude Opus 5.5 (High)",
        )
        s_five = bench.score_campaign(camp)
        self.assertEqual(s_five["decisive"], 5)
        self.assertEqual(s_five["order_flips"], 1)
        self.assertAlmostEqual(s_five["p_value"], 0.0625, places=6)
        self.assertEqual(s_five["verdict"], "not shown")

        # Post-pairing mutation inside judge/pair-BM-01-o1/A/ is caught by digest re-verification
        sub_file = camp / "judge" / "pair-BM-01-o1" / "A" / "submission.diff"
        orig_sub = sub_file.read_bytes()
        sub_file.write_bytes(orig_sub + b"# tampered\n")
        s_sub_tamper = bench.score_campaign(camp)
        self.assertFalse(s_sub_tamper["ok"])
        self.assertEqual(s_sub_tamper["submission_tampered"], 1)
        sub_file.write_bytes(orig_sub)

        # Tampering with .private/key.json aborts verdict evaluation cleanly (and rejects `..` task keys)
        (camp / ".private" / "key.json").write_text(
            (camp / ".private" / "key.json").read_text(encoding="utf-8") + " ",
            encoding="utf-8",
        )
        s_tamper = bench.score_campaign(camp)
        self.assertFalse(s_tamper["seal_valid"])
        self.assertFalse(s_tamper["ok"])
        self.assertEqual(s_tamper["tasks"], [])

        (camp / ".private" / "key.json").write_text(
            json.dumps({"seed": 42, "pairs": {"../outside": {}}}),
            encoding="utf-8",
        )
        with self.assertRaises(bench.IntegrityError):
            bench.score_campaign(camp)

    def test_leak_scan_stripping_verdict_leaks_allowlist_symlinks_and_tamper_guards(self) -> None:
        camp = self.root / "camp_leak"
        bench.init_campaign(camp, seed=7, builder_model="Gemini 4 Neon (XHigh)")
        before_key = (camp / ".private" / "key.json").read_text(encoding="utf-8")

        off_dir = self.root / "off_d"
        on_dir = self.root / "on_d"
        off_dir.mkdir()
        on_dir.mkdir()
        (off_dir / "app.py").write_text("x = 1\n", encoding="utf-8")
        # Harness ledgers in STRIPPED_NAMES must be stripped cleanly before leak scan!
        (on_dir / "tasks.md").write_text("plumbwork campaign ledger\n", encoding="utf-8")
        (on_dir / "HANDOFF.md").write_text("plumb-guard handoff\n", encoding="utf-8")
        (on_dir / "app.py").write_text("# generated by plumbwork harness\nx = 2\n", encoding="utf-8")

        # Content leak fails without mutating key.json
        with self.assertRaises(bench.IntegrityError):
            bench.pair_task(camp, task_id="BM-LEAK", off_src=off_dir, on_src=on_dir)
        self.assertEqual((camp / ".private" / "key.json").read_text(encoding="utf-8"), before_key)
        self.assertFalse((camp / "judge" / "pair-BM-LEAK-o1").exists())

        # Allowlisting "plumbwork" lets pair succeed, strips tasks.md/HANDOFF.md, AND lets verdict cite "plumbwork"
        res_allow = bench.pair_task(camp, task_id="BM-ALLOW", off_src=off_dir, on_src=on_dir, allow_markers=["plumbwork"])
        o1_dir = Path(res_allow["o1_dir"])
        o2_dir = Path(res_allow["o2_dir"])
        self.assertFalse((o1_dir / "A" / "tasks.md").exists())
        self.assertFalse((o1_dir / "B" / "tasks.md").exists())
        self.assertFalse((o1_dir / "B" / "HANDOFF.md").exists())

        # Duplicate task without --force rejected
        with self.assertRaises(bench.BenchmarkError):
            bench.pair_task(camp, task_id="BM-ALLOW", off_src=off_dir, on_src=on_dir, allow_markers=["plumbwork"])

        # Missing verdict -> incomplete
        _write_verdict(o1_dir, winner="A", sealed=res_allow["sealed_o1"], judge_model="Claude Opus 5.5", why="Mentions plumbwork cleanly")
        s_inc = bench.score_campaign(camp)
        self.assertFalse(s_inc["ok"])
        self.assertEqual(s_inc["incomplete"], 1)
        self.assertEqual(s_inc["verdict_leaks"], 0)  # allowlisted token did NOT trigger leak

        # Non-UTF-8 corrupt verdict -> marked incomplete (no crash)
        (o2_dir / "verdict.json").write_bytes(b"\xff\xfe\x00")
        s_bad_utf8 = bench.score_campaign(camp)
        self.assertEqual(s_bad_utf8["incomplete"], 1)

        # Un-allowlisted marker ("key.json") in verdict why -> verdict_leaks=1
        _write_verdict(o2_dir, winner="B", sealed=res_allow["sealed_o2"], judge_model="Claude Opus 5.5", why="Read key.json directly")
        s_vleak = bench.score_campaign(camp)
        self.assertFalse(s_vleak["ok"])
        self.assertEqual(s_vleak["verdict_leaks"], 1)

        # Path leak rejected
        (on_dir / "app.py").write_text("x = 2\n", encoding="utf-8")
        (on_dir / "plumb-guard-notes.txt").write_text("clean body\n", encoding="utf-8")
        with self.assertRaises(bench.IntegrityError):
            bench.pair_task(camp, task_id="BM-PATH", off_src=off_dir, on_src=on_dir)
        (on_dir / "plumb-guard-notes.txt").unlink()

        # Symlinked submission rejected
        if hasattr(os, "symlink"):
            sym_sub = self.root / "sym_on"
            try:
                os.symlink(on_dir, sym_sub)
                sym_created = True
            except (OSError, NotImplementedError):
                sym_created = False
            if sym_created:
                with self.assertRaises(bench.IntegrityError):
                    bench.pair_task(camp, task_id="BM-SYM", off_src=off_dir, on_src=sym_sub)

        # Tampered key.seal causes pair_task to refuse
        (camp / ".private" / "key.seal").write_text("0" * 64 + "\n", encoding="utf-8")
        with self.assertRaises(bench.IntegrityError):
            bench.pair_task(camp, task_id="BM-TAMPER", off_src=off_dir, on_src=on_dir)

    def test_zero_decisive_wilson_and_strict_ledger_validation(self) -> None:
        self.assertEqual(bench.exact_two_sided_sign_test(0, 0), 1.0)
        self.assertIsNone(bench.wilson_95_interval(0, 0))

        base_row = {
            "task_id": "BM-01",
            "tier": 2,
            "condition": "OFF",
            "repo": "demo",
            "base_sha": "abc1234",
            "model": "Gemini 4 Neon (XHigh)",
            "acceptance_pass": 1,
            "rule9_intact": 1,
            "stop_gate_strikes": 0,
            "auditor_confirmed_defects": 0,
            "user_corrections": 0,
            "wall_clock_sec": 60,
            "total_tokens": 10000,
        }
        on_row = {**base_row, "condition": "ON", "total_tokens": 12000}
        # Tier-3 +80% pair must be excluded from Tier 1/2 budget calculation
        t3_off = {**base_row, "task_id": "BM-10", "tier": 3, "total_tokens": 50000}
        t3_on = {**t3_off, "condition": "ON", "total_tokens": 90000}

        ok_jsonl = self.root / "ok.jsonl"
        ok_jsonl.write_text(
            "\n".join(json.dumps(r) for r in (base_row, on_row, t3_off, t3_on)) + "\n",
            encoding="utf-8",
        )
        lr = bench.score_ledger(ok_jsonl)
        self.assertTrue(lr["ok"])
        self.assertEqual(lr["tier12_pairs"], 1)
        self.assertAlmostEqual(lr["tier12_token_delta_pct"], 20.0, places=2)

        # Tier 1/2 > +25% fails budget cleanly (ok=False)
        over_jsonl = self.root / "over.jsonl"
        over_jsonl.write_text(
            json.dumps(base_row) + "\n" + json.dumps({**on_row, "total_tokens": 12600}) + "\n",
            encoding="utf-8",
        )
        lr_over = bench.score_ledger(over_jsonl)
        self.assertFalse(lr_over["ok"])
        self.assertAlmostEqual(lr_over["tier12_token_delta_pct"], 26.0, places=2)

        # Invalid rows: bool acceptance_pass, bool tier, float counter, negative tokens, mismatched tier, unpaired
        for label, rows in (
            ("bool_pass", [{**base_row, "acceptance_pass": True}, on_row]),
            ("bool_tier", [{**base_row, "tier": True}, on_row]),
            ("float_strikes", [{**base_row, "stop_gate_strikes": 0.9}, on_row]),
            ("neg_tokens", [{**base_row, "total_tokens": -1}, on_row]),
            ("tier_mismatch", [base_row, {**on_row, "tier": 3}]),
            ("unpaired", [base_row]),
        ):
            with self.subTest(label=label):
                p = self.root / f"{label}.jsonl"
                p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
                with self.assertRaises(bench.IntegrityError):
                    bench.score_ledger(p)

        # off_med == 0 < on_med fails budget cleanly
        zero_off = self.root / "zero_off.jsonl"
        zero_off.write_text(
            json.dumps({**base_row, "total_tokens": 0}) + "\n" + json.dumps(on_row) + "\n",
            encoding="utf-8",
        )
        lr_zero = bench.score_ledger(zero_off)
        self.assertIsNone(lr_zero["tier12_token_delta_pct"])
        self.assertFalse(lr_zero["ok"])

    def test_cli_init_pair_score_subcommands_and_exit_codes(self) -> None:
        script = str(REPO_ROOT / "scripts" / "benchmark_eval.py")
        camp = self.root / "cli_camp"

        r_init = subprocess.run(
            [sys.executable, script, "init", "--out", str(camp), "--seed", "9", "--builder-model", "Gemini 4 Neon", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_init.returncode, 0, r_init.stderr)

        # Missing --ledger/--campaign -> exit 2
        r_no_arg = subprocess.run([sys.executable, script, "score", "--json"], capture_output=True, text=True, check=False)
        self.assertEqual(r_no_arg.returncode, 2)

        off_f = self.root / "off.diff"
        on_f = self.root / "on.diff"
        off_f.write_text("a\n", encoding="utf-8")
        on_f.write_text("b\n", encoding="utf-8")
        r_pair = subprocess.run(
            [sys.executable, script, "pair", "--campaign", str(camp), "--task", "BM-01", "--off", str(off_f), "--on", str(on_f), "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_pair.returncode, 0, r_pair.stderr)
        p_out = json.loads(r_pair.stdout)
        _write_verdict(Path(p_out["o1_dir"]), winner="A", sealed=p_out["sealed_o1"], judge_model="Claude Opus 5.5")
        _write_verdict(Path(p_out["o2_dir"]), winner="B", sealed=p_out["sealed_o2"], judge_model="Claude Opus 5.5")

        # 1 decisive pair -> valid (exit 0) without --require-ahead, exit 1 with --require-ahead
        r_s0 = subprocess.run([sys.executable, script, "score", "--campaign", str(camp), "--json"], capture_output=True, text=True, check=False)
        self.assertEqual(r_s0.returncode, 0, r_s0.stderr)
        self.assertEqual(json.loads(r_s0.stdout)["campaign"]["verdict"], "not shown")

        r_s1 = subprocess.run(
            [sys.executable, script, "score", "--campaign", str(camp), "--require-ahead", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r_s1.returncode, 1)


class TestAdr0018UpstreamTrackingAndNotices(unittest.TestCase):
    def test_100x_release_tracking_parity_and_plugin_pack_notices(self) -> None:
        seed_path = REPO_ROOT / "skills" / "upstream-auditor" / "upstream_state.seed.json"
        seed = json.loads(seed_path.read_text(encoding="utf-8"))
        tracked = seed.get("tracked_repositories", {})
        self.assertEqual(len(tracked), 9)
        entry = tracked.get("100x-engineer-skill")
        self.assertIsInstance(entry, dict)
        self.assertEqual(entry["repo"], "DeadInternetStudios/100x-engineer-skill")
        self.assertEqual(entry["track"], "release")
        self.assertEqual(entry["last_synced_commit"], "v0.1.1")

        # Fallback dictionary in guard/upstream.py must mirror seed identically
        with tempfile.TemporaryDirectory(prefix="plumbwork_adr0018_up_") as td:
            empty_cfg = Path(td) / "cfg"
            empty_cfg.mkdir()
            with mock.patch.dict(
                os.environ,
                {
                    "ANTIGRAVITY_CONFIG_DIR": str(empty_cfg),
                    "UPSTREAM_STATE_FILE": str(Path(td) / "missing_state.json"),
                },
                clear=False,
            ):
                fallback = guard_upstream.UpstreamAuditorBridge(target_dir=empty_cfg).load_state()
        self.assertEqual(fallback["tracked_repositories"], tracked)

        # Standalone ui-refinery plugin pack bundles check_ui_matrix.py and scopes 100x attribution strictly to UI matrix (no core harness leak)
        with tempfile.TemporaryDirectory(prefix="plumbwork_adr0018_pack_") as td:
            out_dir = Path(td) / "packs"
            guard_plugins.build_all_plugin_packs(REPO_ROOT, out_dir, validate=True)
            ui_pack = out_dir / "ui-refinery"
            self.assertTrue((ui_pack / "skills" / "ui-refinery" / "scripts" / "check_ui_matrix.py").is_file())
            notices = (ui_pack / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
            readme = (ui_pack / "README.md").read_text(encoding="utf-8")
            self.assertIn("DeadInternetStudios/100x-engineer-skill", notices)
            self.assertIn("Copyright (c) 2026 Dead Internet Studios", notices)
            self.assertIn("DeadInternetStudios/100x-engineer-skill", readme)
            self.assertNotIn("property ledger", readme.lower())
            self.assertNotIn("benchmark evaluation", readme.lower())
            self.assertNotIn("property ledger", notices.lower())
            self.assertNotIn("benchmark evaluation", notices.lower())


if __name__ == "__main__":
    unittest.main()
