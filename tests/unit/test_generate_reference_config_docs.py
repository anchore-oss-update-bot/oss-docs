import re
from dataclasses import replace
from pathlib import Path

import pytest

from generate_reference_config_docs import generate_markdown_content
from utils.config import paths


@pytest.fixture
def syft_config_cache(tmp_path: Path, monkeypatch) -> Path:
    """Create a mock cache directory with sample syft config output."""
    cache_dir = tmp_path / "data" / "syft" / "config"
    cache_dir.mkdir(parents=True)

    # sample config output with correct paths (as would be generated with HOME=/root)
    config_output = """log:
  quiet: false
  level: 'warn'

golang:
  local-mod-cache-dir: '~/go/pkg/mod'

java:
  maven-local-repository-dir: '~/.m2/repository'

cache:
  dir: '~/.cache/syft'
"""
    (cache_dir / "output.txt").write_text(config_output)

    # create version cache
    version_dir = tmp_path / "data" / "syft" / "version"
    version_dir.mkdir(parents=True)
    (version_dir / "output.txt").write_text("1.0.0\n")

    # create a new Paths instance with modified reference_cache_dir
    new_paths = replace(paths, reference_cache_dir=tmp_path / "data")
    monkeypatch.setattr("utils.config.paths", new_paths)
    monkeypatch.setattr("generate_reference_config_docs.config.paths", new_paths)

    return cache_dir


@pytest.fixture
def grype_config_cache(tmp_path: Path, monkeypatch) -> Path:
    """Create a mock cache directory with sample grype config output."""
    cache_dir = tmp_path / "data" / "grype" / "config"
    cache_dir.mkdir(parents=True)

    # sample config output with correct paths
    config_output = """log:
  quiet: false
  level: 'warn'

db:
  cache-dir: '~/.cache/grype/db'
"""
    (cache_dir / "output.txt").write_text(config_output)

    # create version cache
    version_dir = tmp_path / "data" / "grype" / "version"
    version_dir.mkdir(parents=True)
    (version_dir / "output.txt").write_text("0.80.0\n")

    # create a new Paths instance with modified reference_cache_dir
    new_paths = replace(paths, reference_cache_dir=tmp_path / "data")
    monkeypatch.setattr("utils.config.paths", new_paths)
    monkeypatch.setattr("generate_reference_config_docs.config.paths", new_paths)

    return cache_dir


class TestPathMangling:
    """Tests to ensure configuration paths are not mangled."""

    def test_syft_config_paths_not_mangled(self, syft_config_cache: Path) -> None:
        """Verify syft config output contains properly formatted paths."""
        content = generate_markdown_content(
            image="anchore/syft:latest",
            app_name="syft",
            tool_name="syft",
            update=False,
        )

        # check that proper paths are present
        assert "~/go/pkg/mod" in content, "Go module cache path should use ~/ not ~"
        assert "~/.m2/repository" in content, "Maven repository path should use ~/."
        assert "~/.cache/syft" in content, "Cache dir path should use ~/."

        # check that mangled paths are NOT present
        assert "~go~pkg~mod" not in content, "Go path should not be mangled"
        assert "~.m2~repository" not in content, "Maven path should not be mangled"
        assert "~.cache~syft" not in content, "Cache path should not be mangled"

    def test_grype_config_paths_not_mangled(self, grype_config_cache: Path) -> None:
        """Verify grype config output contains properly formatted paths."""
        content = generate_markdown_content(
            image="anchore/grype:latest",
            app_name="grype",
            tool_name="grype",
            update=False,
        )

        # check that proper paths are present
        assert "~/.cache/grype/db" in content, "Cache dir path should use ~/."

        # check that mangled paths are NOT present
        assert "~.cache~grype~db" not in content, "Cache path should not be mangled"

    @pytest.mark.parametrize(
        "mangled_pattern,description",
        [
            (
                r"~[^/\s]+~[^/\s]+~",
                "tilde-separated path components (like ~.cache~syft)",
            ),
            (r"'~[a-z0-9]+~", "path starting with tilde followed by word and tilde"),
        ],
    )
    def test_no_mangled_path_patterns(
        self, syft_config_cache: Path, mangled_pattern: str, description: str
    ) -> None:
        """Check for common mangled path patterns in syft config output."""
        content = generate_markdown_content(
            image="anchore/syft:latest",
            app_name="syft",
            tool_name="syft",
            update=False,
        )

        matches = re.findall(mangled_pattern, content)
        assert not matches, f"Found {description}: {matches}"


class TestConfigGeneration:
    """Tests for config generation functionality."""

    def test_syft_config_contains_yaml_block(self, syft_config_cache: Path) -> None:
        """Verify generated content contains YAML code block."""
        content = generate_markdown_content(
            image="anchore/syft:latest",
            app_name="syft",
            tool_name="syft",
            update=False,
        )

        assert "```yaml" in content
        assert "```" in content
        assert "log:" in content

    def test_grype_config_contains_yaml_block(self, grype_config_cache: Path) -> None:
        """Verify generated content contains YAML code block."""
        content = generate_markdown_content(
            image="anchore/grype:latest",
            app_name="grype",
            tool_name="grype",
            update=False,
        )

        assert "```yaml" in content
        assert "```" in content
        assert "log:" in content

    def test_syft_config_contains_version_info(self, syft_config_cache: Path) -> None:
        """Verify generated content includes version information."""
        content = generate_markdown_content(
            image="anchore/syft:latest",
            app_name="syft",
            tool_name="syft",
            update=False,
        )

        # version info is included even if it's "unknown" from cache miss
        assert "Syft version" in content
        assert "{{< alert" in content

    def test_grype_config_contains_version_info(self, grype_config_cache: Path) -> None:
        """Verify generated content includes version information."""
        content = generate_markdown_content(
            image="anchore/grype:latest",
            app_name="grype",
            tool_name="grype",
            update=False,
        )

        # version info is included even if it's "unknown" from cache miss
        assert "Grype version" in content
        assert "{{< alert" in content

    def test_config_contains_search_locations(self, syft_config_cache: Path) -> None:
        """Verify generated content includes config search locations."""
        content = generate_markdown_content(
            image="anchore/syft:latest",
            app_name="syft",
            tool_name="syft",
            update=False,
        )

        assert "./.syft.yaml" in content
        assert "./.syft/config.yaml" in content
        assert "~/.syft.yaml" in content
        assert "$XDG_CONFIG_HOME/syft/config.yaml" in content
