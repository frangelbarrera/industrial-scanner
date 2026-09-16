"""Test suite for ics_scanner.security primitives."""

from __future__ import annotations

import pytest

from ics_scanner.security import (
    TargetPolicyError,
    filter_targets,
    html_escape,
    is_safe_target,
    safe_join_path,
    safe_render,
)


class TestHtmlEscape:
    def test_escapes_angle_brackets(self):
        assert html_escape("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"

    def test_escapes_quotes(self):
        assert html_escape('"onerror="alert(1)') == "&quot;onerror=&quot;alert(1)"

    def test_handles_none(self):
        assert html_escape(None) == ""

    def test_handles_list(self):
        assert html_escape(["<a>", "<b>"]) == "&lt;a&gt;, &lt;b&gt;"

    def test_handles_bytes(self):
        assert html_escape(b"<x>") == "&lt;x&gt;"


class TestSafeRender:
    def test_renders_with_autoescape(self, tmp_path):
        tmpl = tmp_path / "t.html"
        tmpl.write_text("<div>{{ value }}</div>", encoding="utf-8")
        out = safe_render("t.html", {"value": "<script>"}, template_dir=str(tmp_path))
        assert out == "<div>&lt;script&gt;</div>"

    def test_renders_safe_value_as_is(self, tmp_path):
        tmpl = tmp_path / "t.html"
        tmpl.write_text("<div>{{ value }}</div>", encoding="utf-8")
        # markupsafe.Markup would bypass, but plain string with autoescape escapes.
        out = safe_render("t.html", {"value": "plain"}, template_dir=str(tmp_path))
        assert out == "<div>plain</div>"


class TestIsSafeTarget:
    def test_loopback_allowed(self):
        assert is_safe_target("127.0.0.1") is True

    def test_rfc1918_allowed(self):
        assert is_safe_target("192.168.1.10") is True
        assert is_safe_target("10.0.0.1") is True
        assert is_safe_target("172.16.5.5") is True

    def test_public_refused_by_default(self):
        with pytest.raises(TargetPolicyError):
            is_safe_target("8.8.8.8")

    def test_public_allowed_with_flag(self):
        assert is_safe_target("8.8.8.8", allow_public=True) is True

    @pytest.mark.parametrize(
        "target",
        [
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ],
    )
    def test_public_ipv6_transition_targets_are_refused(self, target):
        with pytest.raises(TargetPolicyError):
            is_safe_target(target)

    def test_private_ipv4_mapped_target_is_allowed(self):
        assert is_safe_target("::ffff:192.168.1.1") is True

    def test_transition_target_is_allowed_with_explicit_authorization(self):
        assert is_safe_target("::ffff:8.8.8.8", allow_public=True) is True

    def test_cidr_size_limit(self):
        with pytest.raises(TargetPolicyError):
            is_safe_target("10.0.0.0/8")

    def test_invalid_input(self):
        with pytest.raises(TargetPolicyError):
            is_safe_target("not-an-ip")


class TestFilterTargets:
    def test_filters_out_public(self):
        targets = ["192.168.1.1", "8.8.8.8", "127.0.0.1"]
        safe = filter_targets(targets)
        assert "8.8.8.8" not in safe
        assert "192.168.1.1" in safe
        assert "127.0.0.1" in safe


class TestSafeJoinPath:
    def test_blocks_traversal(self, tmp_path):
        with pytest.raises(ValueError):
            safe_join_path(str(tmp_path), "../../etc/passwd")

    def test_allows_normal_join(self, tmp_path):
        p = safe_join_path(str(tmp_path), "reports", "out.json")
        assert str(p).endswith("reports/out.json")
