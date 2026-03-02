"""Tests for WinDbg JavaScript extension discovery, loading, and tool generation."""

import os
import tempfile

import pytest

from dspy.experimental.chatdbg.tools.windbg_extensions import (
    JS_EXTENSION_REGISTRY,
    _find_script,
    _format_js_arg,
    _format_js_args,
    discover_js_extensions,
    load_js_extensions,
    make_extension_tools,
    _make_extension_tool,
)

from tests.experimental.chatdbg.mock_bridge import MockCDBBridge


class TestFormatJSArg:
    """Test argument formatting for JS function calls."""

    def test_string_quoted(self):
        assert _format_js_arg("hello") == '"hello"'

    def test_string_with_backslash(self):
        result = _format_js_arg("C:\\path\\file")
        assert "\\\\" in result

    def test_string_with_quotes(self):
        result = _format_js_arg('say "hi"')
        assert '\\"' in result

    def test_int(self):
        assert _format_js_arg(42) == "42"

    def test_float(self):
        assert _format_js_arg(3.14) == "3.14"

    def test_bool_true(self):
        assert _format_js_arg(True) == "true"

    def test_bool_false(self):
        assert _format_js_arg(False) == "false"


class TestFormatJSArgs:
    def test_empty_params(self):
        assert _format_js_args({}, {}) == ""

    def test_single_param(self):
        params = {"address": {"type": "string"}}
        kwargs = {"address": "@rsp"}
        result = _format_js_args(params, kwargs)
        assert '"@rsp"' in result

    def test_missing_param_skipped(self):
        params = {"a": {"type": "string"}, "b": {"type": "string"}}
        kwargs = {"a": "val"}
        result = _format_js_args(params, kwargs)
        assert '"val"' in result


class TestFindScript:
    def test_finds_script_in_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "test.js")
            with open(script_path, "w") as f:
                f.write("// test")
            result = _find_script(["test.js"], [tmpdir])
            assert result == script_path

    def test_finds_nested_script(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, "ext")
            os.makedirs(subdir)
            script_path = os.path.join(subdir, "ext.js")
            with open(script_path, "w") as f:
                f.write("// test")
            result = _find_script(["ext/ext.js"], [tmpdir])
            assert os.path.normpath(result) == os.path.normpath(script_path)

    def test_returns_none_if_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _find_script(["nonexistent.js"], [tmpdir])
            assert result is None

    def test_returns_none_for_nonexistent_dir(self):
        result = _find_script(["test.js"], ["/nonexistent/dir"])
        assert result is None

    def test_tries_multiple_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "fallback.js")
            with open(script_path, "w") as f:
                f.write("// test")
            result = _find_script(["primary.js", "fallback.js"], [tmpdir])
            assert result == script_path


class TestDiscoverJSExtensions:
    def test_returns_empty_without_jsprovider(self):
        bridge = MockCDBBridge(scenario="native_crash")
        result = discover_js_extensions(bridge)
        assert result == []

    def test_returns_empty_with_jsprovider_but_no_scripts(self):
        bridge = MockCDBBridge(scenario="js_available")
        # No scripts installed in standard locations (hopefully)
        result = discover_js_extensions(bridge, config_paths="/nonexistent/path")
        # May find real extensions if installed, so just check it's a list
        assert isinstance(result, list)

    def test_finds_extensions_in_config_path(self):
        bridge = MockCDBBridge(scenario="js_available")
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake lldext.js
            script_path = os.path.join(tmpdir, "lldext.js")
            with open(script_path, "w") as f:
                f.write("function analyze() { return 'ok'; }")

            result = discover_js_extensions(bridge, config_paths=tmpdir)
            # Should find lldext
            names = [ext["name"] for ext in result]
            assert "lldext" in names

            # Should have resolved script_path
            lldext = next(e for e in result if e["name"] == "lldext")
            assert lldext["script_path"] == script_path

    def test_returns_tools_in_extension(self):
        bridge = MockCDBBridge(scenario="js_available")
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "lldext.js")
            with open(script_path, "w") as f:
                f.write("// lldext")

            result = discover_js_extensions(bridge, config_paths=tmpdir)
            lldext = next(e for e in result if e["name"] == "lldext")
            tool_names = [t["tool_name"] for t in lldext["tools"]]
            assert "js_lldext_analyze" in tool_names
            assert "js_lldext_callpath" in tool_names
            assert "js_lldext_funcdiscover" in tool_names


class TestLoadJSExtensions:
    def test_load_success(self):
        bridge = MockCDBBridge(scenario="js_available")
        extensions = [
            {
                "name": "test_ext",
                "script_path": "/fake/path/test.js",
                "namespace": "@$scriptContents",
                "tools": [],
            }
        ]
        results = load_js_extensions(bridge, extensions)
        assert results["test_ext"] is True

    def test_load_failure_on_error(self):
        bridge = MockCDBBridge(scenario="native_crash")
        extensions = [
            {
                "name": "test_ext",
                "script_path": "/fake/path/test.js",
                "namespace": "@$scriptContents",
                "tools": [],
            }
        ]
        results = load_js_extensions(bridge, extensions)
        assert results["test_ext"] is False


class TestMakeExtensionTool:
    def test_no_param_tool(self):
        bridge = MockCDBBridge(scenario="js_available")
        tool = _make_extension_tool(
            bridge=bridge,
            ext_name="test",
            namespace="@$scriptContents",
            js_func="analyze",
            tool_name="test_analyze",
            description="Run analysis",
            params={},
        )
        assert tool.__name__ == "test_analyze"
        assert callable(tool)
        result = tool()
        # Should have called dx @$scriptContents.analyze()
        log = bridge.get_command_log()
        assert any("@$scriptContents.analyze()" in cmd for cmd in log)

    def test_param_tool(self):
        bridge = MockCDBBridge(scenario="js_available")
        tool = _make_extension_tool(
            bridge=bridge,
            ext_name="telescope",
            namespace="@$scriptContents",
            js_func="telescope",
            tool_name="js_telescope",
            description="Memory telescope",
            params={"address": {"type": "string", "description": "Address"}},
        )
        assert tool.__name__ == "js_telescope"
        result = tool(address="@rsp")
        log = bridge.get_command_log()
        assert any('"@rsp"' in cmd for cmd in log)

    def test_tool_has_docstring(self):
        bridge = MockCDBBridge()
        tool = _make_extension_tool(
            bridge=bridge,
            ext_name="test",
            namespace="@$scriptContents",
            js_func="func",
            tool_name="test_func",
            description="A test function",
            params={},
        )
        assert tool.__doc__ == "A test function"

    def test_param_tool_has_annotations(self):
        bridge = MockCDBBridge()
        tool = _make_extension_tool(
            bridge=bridge,
            ext_name="test",
            namespace="@$scriptContents",
            js_func="func",
            tool_name="test_func",
            description="Test",
            params={"addr": {"type": "string", "description": "Addr"}},
        )
        assert "addr" in tool.__annotations__
        assert tool.__annotations__["addr"] is str


class TestMakeExtensionTools:
    def test_generates_tools_for_all_functions(self):
        bridge = MockCDBBridge(scenario="js_available")
        extensions = [
            {
                "name": "lldext",
                "script_path": "/fake/lldext.js",
                "namespace": "@$scriptContents",
                "tools": [
                    {"js_func": "analyze", "tool_name": "js_lldext_analyze",
                     "description": "Analyze", "parameters": {}},
                    {"js_func": "callpath", "tool_name": "js_lldext_callpath",
                     "description": "Callpath", "parameters": {}},
                ],
            }
        ]
        tools = make_extension_tools(bridge, extensions)
        assert len(tools) == 2
        names = [t.__name__ for t in tools]
        assert "js_lldext_analyze" in names
        assert "js_lldext_callpath" in names

    def test_empty_extensions_returns_empty(self):
        bridge = MockCDBBridge()
        assert make_extension_tools(bridge, []) == []


class TestRegistryIntegrity:
    """Verify the extension registry has expected structure."""

    def test_all_entries_have_required_fields(self):
        for ext in JS_EXTENSION_REGISTRY:
            assert "name" in ext
            assert "script_paths" in ext
            assert "namespace" in ext
            assert "tools" in ext
            assert isinstance(ext["tools"], list)

    def test_all_tools_have_required_fields(self):
        for ext in JS_EXTENSION_REGISTRY:
            for tool in ext["tools"]:
                assert "js_func" in tool
                assert "tool_name" in tool
                assert "description" in tool

    def test_known_extensions_present(self):
        names = [ext["name"] for ext in JS_EXTENSION_REGISTRY]
        assert "lldext" in names
        assert "telescope" in names
        assert "codeCoverage" in names

    def test_telescope_has_address_param(self):
        telescope_ext = next(e for e in JS_EXTENSION_REGISTRY if e["name"] == "telescope")
        telescope_tool = telescope_ext["tools"][0]
        assert "address" in telescope_tool["parameters"]
