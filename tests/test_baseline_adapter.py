"""Adapter-fidelity checks for the frozen corrected legacy copy.

Skipped unless DA_ADKG_C_PATH points to an unmodified corrected copy."""

import os
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from baselines import da_adkg_c  # noqa: E402

PATH = os.environ.get("DA_ADKG_C_PATH")


class AdapterTests(unittest.TestCase):
    def test_modified_copy_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            for name in da_adkg_c.expected_hashes():
                Path(d, name).write_text("# not the baseline\n")
            with self.assertRaises(da_adkg_c.BaselineMismatch):
                da_adkg_c.verify(d)

    def test_missing_sources_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(da_adkg_c.BaselineMismatch):
                da_adkg_c.load(d)

    def test_load_handle_does_not_use_cached_module_or_change_sys_path(self):
        with tempfile.TemporaryDirectory() as d:
            data = b"raise AssertionError('load must not execute this file')\n"
            Path(d, "protocol.py").write_bytes(data)
            hashes = {"protocol.py": hashlib.sha256(data).hexdigest()}
            fake = types.ModuleType("protocol")
            before = list(sys.path)
            with patch.object(da_adkg_c, "expected_hashes", return_value=hashes), \
                    patch.dict(sys.modules, {"protocol": fake}):
                handle = da_adkg_c.load(d)
                self.assertIsInstance(handle, da_adkg_c.FrozenBaseline)
                self.assertIs(sys.modules["protocol"], fake)
                self.assertEqual(sys.path, before)

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_cached_modules_and_pythonpath_cannot_substitute_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("protocol", "crypto", "network"):
                Path(d, name + ".py").write_text("raise AssertionError('shadow module ran')\n")
            cached = {name: types.ModuleType(name)
                      for name in ("protocol", "crypto", "network")}
            before = list(sys.path)
            with patch.dict(sys.modules, cached), patch.dict(os.environ, {"PYTHONPATH": d}):
                result = da_adkg_c.honest_smoke(PATH)
                self.assertTrue(result["success"], result)
                self.assertEqual(result["execution"], "isolated_verified_snapshot")
                self.assertEqual(result["source_sha256"], da_adkg_c.expected_hashes())
                self.assertEqual(result["loaded_source_files"], ["crypto.py", "protocol.py"])
                for name, module in cached.items():
                    self.assertIs(sys.modules[name], module)
            self.assertEqual(sys.path, before)

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_worker_refuses_files_changed_after_handle_creation(self):
        with tempfile.TemporaryDirectory() as d:
            for name in da_adkg_c.expected_hashes():
                Path(d, name).write_bytes(Path(PATH, name).read_bytes())
            handle = da_adkg_c.load(d)
            Path(d, "crypto.py").write_text("raise AssertionError('changed source ran')\n")
            with self.assertRaisesRegex(da_adkg_c.BaselineMismatch, "crypto.py"):
                handle.honest_smoke()

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_pythonpath_cannot_shadow_worker_stdlib(self):
        # Fails if the worker loses -I: these names are imported before verification.
        with tempfile.TemporaryDirectory() as d:
            for name in ("hashlib", "json", "tempfile", "importlib"):
                Path(d, name + ".py").write_text("raise SystemExit('shadow stdlib ran')\n")
            with patch.dict(os.environ, {"PYTHONPATH": d}):
                self.assertTrue(da_adkg_c.honest_smoke(PATH)["success"])

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_symlinked_temporary_directory(self):
        with tempfile.TemporaryDirectory() as real:
            link = real + "_link"
            try:
                os.symlink(real, link)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            try:
                with patch.dict(os.environ, {"TMPDIR": link}):
                    self.assertTrue(da_adkg_c.honest_smoke(PATH)["success"])
            finally:
                os.unlink(link)

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_manifest_change_after_handle_creation_is_refused(self):
        # Work on a private copy of the adapter so the repository manifest is untouched.
        with tempfile.TemporaryDirectory() as d:
            sources = Path(d, "sources")
            sources.mkdir()
            for name in da_adkg_c.expected_hashes():
                shutil.copy(Path(PATH, name), sources / name)
            for name in ("da_adkg_c.py", "_frozen_worker.py", "manifest.json"):
                shutil.copy(Path(da_adkg_c.__file__).with_name(name), d)
            spec = importlib.util.spec_from_file_location("adapter_copy", Path(d, "da_adkg_c.py"))
            copy = importlib.util.module_from_spec(spec)
            with patch.dict(sys.modules, {"adapter_copy": copy}):
                spec.loader.exec_module(copy)
                handle = copy.load(sources)
                protocol = sources / "protocol.py"
                protocol.write_bytes(protocol.read_bytes() + b"\n# edited after handle creation\n")
                changed = dict(copy.expected_hashes(), **{
                    "protocol.py": hashlib.sha256(protocol.read_bytes()).hexdigest()})
                Path(d, "manifest.json").write_text(json.dumps({"files": changed}))
                with self.assertRaisesRegex(copy.BaselineMismatch, "manifest changed"):
                    handle.honest_smoke()

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_hashes_match_manifest(self):
        self.assertEqual(set(da_adkg_c.verify(PATH)), set(da_adkg_c.expected_hashes()))

    @unittest.skipUnless(PATH, "set DA_ADKG_C_PATH to the frozen corrected copy")
    def test_honest_run_smoke(self):
        r = da_adkg_c.honest_smoke(PATH)
        self.assertTrue(r["success"], r)
        self.assertEqual(r["qual"], [1, 2, 3, 4])
        self.assertTrue(all(r["audit"].values()))
        self.assertEqual(r["target"], "adversary_fixed_corrupt_shares")


if __name__ == "__main__":
    unittest.main()
