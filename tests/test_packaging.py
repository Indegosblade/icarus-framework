"""Regression: built artifacts must ship parser manifests, the manifest JSON
Schema, and the parser catalogs — not only the .py files.

Guards the packaging defect where ``[tool.setuptools.package-data]`` declared only
``py.typed``, so the wheel and sdist shipped no ``*.yaml`` / ``*.json`` runtime data.
On such an install, ``icarus parser list`` reported every parser as tier "unknown"
and ``icarus parser validate`` raised FileNotFoundError on the schema, while CI stayed
green because it installs the project editable (files present on disk in the source
tree). These tests build the real artifacts and assert the data is present.
"""
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("build", reason="`pip install build` to run packaging tests")

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_YAML = {
    "icarus/parsers/linux.yaml",
    "icarus/parsers/macos.yaml",
    "icarus/parsers/windows.yaml",
    "icarus/parsers/cloud/aws/cloudtrail.yaml",
    "icarus/parsers/generic/archive_parser.yaml",
    "icarus/parsers/generic/binary_entropy_parser.yaml",
    "icarus/parsers/generic/json_parser.yaml",
    "icarus/parsers/generic/sqlite_parser.yaml",
    "icarus/parsers/generic/xml_parser.yaml",
    "icarus/parsers/network/deploy_scripts.yaml",
    "icarus/parsers/network/privacy_stack.yaml",
}
EXPECTED_JSON = {
    "icarus/parsers/schema/parser_manifest.schema.json",
    "icarus/parsers/catalog/parsers.json",
    "icarus/parsers/catalog/parsers-devel.json",
}
EXPECTED = EXPECTED_YAML | EXPECTED_JSON


@pytest.fixture(scope="module")
def built_dists(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    try:
        subprocess.run(
            [sys.executable, "-m", "build", "--no-isolation",
             "--outdir", str(out), str(REPO_ROOT)],
            check=True, capture_output=True, text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        detail = getattr(exc, "stderr", "") or ""
        pytest.skip(f"could not build distributions: {exc}\n{detail[-500:]}")
    whl = next(iter(out.glob("*.whl")), None)
    sdist = next(iter(out.glob("*.tar.gz")), None)
    if not whl or not sdist:
        pytest.skip("build produced no wheel/sdist")
    return whl, sdist


def test_wheel_ships_parser_runtime_data(built_dists):
    whl, _ = built_dists
    names = set(zipfile.ZipFile(whl).namelist())
    missing = EXPECTED - names
    assert not missing, f"wheel is missing runtime data files: {sorted(missing)}"


def test_sdist_ships_parser_runtime_data(built_dists):
    _, sdist = built_dists
    with tarfile.open(sdist) as tf:
        # entries are prefixed with 'icarus_framework-<version>/'; strip it.
        names = {"/".join(n.split("/")[1:]) for n in tf.getnames()}
    missing = EXPECTED - names
    assert not missing, f"sdist is missing runtime data files: {sorted(missing)}"
