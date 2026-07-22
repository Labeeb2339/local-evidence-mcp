"""Render the README boundary map from code, example policy, and test inventory."""

from __future__ import annotations

import argparse
import ast
import hashlib
import sys
import xml.etree.ElementTree as ET
from html import escape
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
TEST_FILE = ROOT / "tests" / "test_server.py"
EXAMPLE_ROOT = ROOT / "examples" / "vault"
EXAMPLE_POLICY = ROOT / "examples" / "policy.example.json"
OUTPUT = ROOT / "docs" / "assets" / "local-evidence-boundary.svg"

sys.path.insert(0, str(SOURCE))
from local_evidence_mcp.server import EvidenceStore, tool_definitions  # noqa: E402


CONTROL_GROUPS = {
    "policy boundary": {
        "test_allowlist_excludes_private_and_non_markdown_files",
        "test_paths_reject_absolute_traversal_wildcards_and_streams",
        "test_large_file_is_rejected",
        "test_linked_files_are_not_indexed",
        "test_invalid_remote_embedding_endpoint_is_rejected",
        "test_status_is_explicit_about_absent_capabilities",
    },
    "retrieval + privacy": {
        "test_read_redacts_credentials_and_raw_flags",
        "test_lexical_search_is_deterministic_fallback",
        "test_semantic_search_cache_contains_vectors_not_plaintext",
        "test_search_rejects_sensitive_query",
        "test_disabled_embeddings_do_not_create_a_network_client",
    },
    "write semantics": {
        "test_create_note_is_create_only",
        "test_create_note_rejects_unknown_fields",
        "test_writes_reject_credentials_and_raw_flags",
        "test_append_lesson_preserves_existing_content",
    },
    "MCP protocol": {
        "test_initialize_and_tool_inventory",
        "test_tool_policy_error_is_returned_as_mcp_tool_error",
        "test_invalid_request_and_unknown_method_use_jsonrpc_errors",
    },
}


def _test_names() -> set[str]:
    tree = ast.parse(TEST_FILE.read_text(encoding="utf-8"), filename=str(TEST_FILE))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _source_data() -> dict[str, Any]:
    names = _test_names()
    categorized = set().union(*CONTROL_GROUPS.values())
    duplicates = sum(len(group) for group in CONTROL_GROUPS.values()) - len(categorized)
    if duplicates:
        raise ValueError("a test appears in more than one control group")
    missing = names - categorized
    stale = categorized - names
    if missing or stale:
        raise ValueError(
            f"control inventory is out of date; uncategorized={sorted(missing)}, "
            f"missing={sorted(stale)}"
        )

    cache_path = ROOT / ".readme-asset-cache.json"
    store = EvidenceStore(EXAMPLE_ROOT, EXAMPLE_POLICY, cache_path)
    status = store.status()
    tools = tool_definitions()
    return {
        "allowed_files": store.allowed_files(),
        "tool_count": len(tools),
        "tool_names": [tool["name"] for tool in tools],
        "execution_capabilities": status["execution_capabilities"],
        "explicitly_absent": status["explicitly_absent"],
        "control_groups": {name: len(tests) for name, tests in CONTROL_GROUPS.items()},
        "test_count": len(names),
    }


def _svg(data: dict[str, Any]) -> str:
    allowed_files = data["allowed_files"]
    tool_count = int(data["tool_count"])
    execution_count = len(data["execution_capabilities"])
    absent = data["explicitly_absent"]
    groups = data["control_groups"]
    test_count = int(data["test_count"])

    width = 1200
    height = 720
    group_colours = ["#6f416f", "#447d6a", "#c57945", "#596f98"]
    track_left = 58
    track_width = 704
    x_cursor = track_left

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">',
        '<title id="title">Local Evidence MCP policy boundary and executable control inventory</title>',
        (
            f'<desc id="desc">The checked-in example policy exposes {len(allowed_files)} '
            f"synthetic files through {tool_count} MCP tools and advertises "
            f"{execution_count} execution capabilities. The test suite contains "
            f"{test_count} named checks grouped by enforced boundary.</desc>"
        ),
        '<rect width="1200" height="720" rx="30" fill="#f7f0e4"/>',
        '<path d="M0 0H1200V14H0Z" fill="#6f416f"/>',
        '<g font-family="Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif">',
        '<text x="58" y="65" fill="#6f416f" font-size="15" font-weight="750" letter-spacing="2.1">LOCAL EVIDENCE MCP / EXAMPLE POLICY</text>',
        '<text x="58" y="118" fill="#332934" font-size="40" font-weight="760">A small evidence boundary, by construction.</text>',
        '<text x="58" y="151" fill="#746a70" font-size="17">The server exposes named evidence operations—not a general route into the machine.</text>',
        '<rect x="58" y="186" width="248" height="84" rx="14" fill="#fffaf2" stroke="#ddd0bf"/>',
        f'<text x="82" y="226" fill="#6f416f" font-size="31" font-weight="770">{len(allowed_files)}</text>',
        '<text x="82" y="250" fill="#746a70" font-size="14">allowlisted example files</text>',
        '<rect x="326" y="186" width="248" height="84" rx="14" fill="#fffaf2" stroke="#ddd0bf"/>',
        f'<text x="350" y="226" fill="#447d6a" font-size="31" font-weight="770">{tool_count}</text>',
        '<text x="350" y="250" fill="#746a70" font-size="14">advertised MCP tools</text>',
        '<rect x="594" y="186" width="248" height="84" rx="14" fill="#332934"/>',
        f'<text x="618" y="226" fill="#f6d8ac" font-size="31" font-weight="770">{execution_count}</text>',
        '<text x="618" y="250" fill="#dfccd9" font-size="14">execution capabilities</text>',
        '<rect x="876" y="70" width="266" height="200" rx="18" fill="#efe3d5" stroke="#d9c9b7"/>',
        '<path d="M911 117h66l15 17h114v88H911Z" fill="#fffaf2" stroke="#6f416f" stroke-width="2"/>',
        '<path d="M911 143h195" stroke="#c3a7bf" stroke-width="2"/>',
        '<circle cx="934" cy="170" r="5" fill="#447d6a"/><circle cx="934" cy="193" r="5" fill="#447d6a"/>',
        '<text x="950" y="175" fill="#4b4047" font-size="13">allowlisted notes</text>',
        '<text x="950" y="198" fill="#4b4047" font-size="13">synthetic fixtures</text>',
        '<text x="1009" y="244" fill="#6f416f" font-size="12" font-weight="700" text-anchor="middle" letter-spacing="1">POLICY-OWNED ROOT</text>',
        '<text x="58" y="316" fill="#746a70" font-size="12" font-weight="750" letter-spacing="1.5">READ PATH</text>',
        '<rect x="58" y="342" width="194" height="76" rx="13" fill="#efe3d5" stroke="#d9c9b7"/>',
        '<text x="155" y="375" fill="#4b4047" font-size="16" font-weight="700" text-anchor="middle">Allowlisted files</text>',
        '<text x="155" y="397" fill="#7d7177" font-size="12" text-anchor="middle">resolved-root guard</text>',
        '<path d="M252 380H290" stroke="#6f416f" stroke-width="2.5"/><path d="m283 373 8 7-8 7" fill="none" stroke="#6f416f" stroke-width="2.5"/>',
        '<rect x="292" y="342" width="194" height="76" rx="13" fill="#f5e3dc" stroke="#dfbeb0"/>',
        '<text x="389" y="375" fill="#70483e" font-size="16" font-weight="700" text-anchor="middle">Redaction</text>',
        '<text x="389" y="397" fill="#866b62" font-size="12" text-anchor="middle">before output + index</text>',
        '<path d="M486 380H524" stroke="#6f416f" stroke-width="2.5"/><path d="m517 373 8 7-8 7" fill="none" stroke="#6f416f" stroke-width="2.5"/>',
        '<rect x="526" y="342" width="194" height="76" rx="13" fill="#e4eee8" stroke="#b9d0c5"/>',
        '<text x="623" y="375" fill="#345e50" font-size="16" font-weight="700" text-anchor="middle">Local retrieval</text>',
        '<text x="623" y="397" fill="#587469" font-size="12" text-anchor="middle">embedding or lexical fallback</text>',
        '<path d="M720 380H758" stroke="#6f416f" stroke-width="2.5"/><path d="m751 373 8 7-8 7" fill="none" stroke="#6f416f" stroke-width="2.5"/>',
        '<rect x="760" y="342" width="194" height="76" rx="13" fill="#e5e9f1" stroke="#bec8dc"/>',
        '<text x="857" y="375" fill="#465979" font-size="16" font-weight="700" text-anchor="middle">Source-labelled result</text>',
        '<text x="857" y="397" fill="#65738d" font-size="12" text-anchor="middle">JSON-RPC over stdio</text>',
        '<rect x="982" y="306" width="160" height="156" rx="15" fill="#332934"/>',
        '<text x="1062" y="336" fill="#f6d8ac" font-size="12" font-weight="750" text-anchor="middle" letter-spacing="1.2">NOT EXPOSED</text>',
    ]

    for index, capability in enumerate(absent):
        x = 998
        y = 360 + index * 17
        lines.append(
            f'<text x="{x}" y="{y}" fill="#dfccd9" font-size="10.5">× {escape(str(capability))}</text>'
        )

    lines.extend(
        [
            '<text x="58" y="486" fill="#746a70" font-size="12" font-weight="750" letter-spacing="1.5">EXECUTABLE CONTROL INVENTORY</text>',
            f'<text x="762" y="486" fill="#746a70" font-size="12" text-anchor="end">{test_count} named tests; count is not a coverage score</text>',
        ]
    )
    for index, (name, count) in enumerate(groups.items()):
        segment_width = track_width * count / test_count
        colour = group_colours[index]
        lines.append(
            f'<rect x="{x_cursor:.1f}" y="508" width="{segment_width:.1f}" height="42" fill="{colour}"/>'
        )
        lines.append(
            f'<text x="{x_cursor + segment_width / 2:.1f}" y="535" fill="#fffaf2" font-size="14" font-weight="740" text-anchor="middle">{count}</text>'
        )
        x_cursor += segment_width

    for index, (name, count) in enumerate(groups.items()):
        x = 58 + (index % 2) * 355
        y = 584 + (index // 2) * 36
        lines.extend(
            [
                f'<circle cx="{x + 7}" cy="{y - 5}" r="7" fill="{group_colours[index]}"/>',
                f'<text x="{x + 23}" y="{y}" fill="#4b4047" font-size="14" font-weight="650">{escape(name)} · {count}</text>',
            ]
        )

    lines.extend(
        [
            '<rect x="806" y="486" width="336" height="132" rx="16" fill="#fffaf2" stroke="#ddd0bf"/>',
            '<text x="830" y="519" fill="#6f416f" font-size="13" font-weight="750" letter-spacing="1.1">WRITE PATH</text>',
            '<text x="830" y="552" fill="#4b4047" font-size="18" font-weight="720">Create-only drafts</text>',
            '<text x="830" y="578" fill="#4b4047" font-size="18" font-weight="720">Append-only lessons</text>',
            '<text x="830" y="602" fill="#7d7177" font-size="12">fixed policy destinations; no overwrite tool</text>',
            '<text x="58" y="680" fill="#7d7177" font-size="13">Derived from the checked-in synthetic policy, server tool definitions, and named tests • not an independent security audit</text>',
            "</g>",
            "</svg>",
            "",
        ]
    )
    return "\n".join(lines)


def _validate_svg(content: str) -> None:
    try:
        ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"generated invalid SVG: {exc}") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the checked-in SVG differs from code, policy, or tests",
    )
    args = parser.parse_args()

    content = _svg(_source_data())
    _validate_svg(content)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != content:
            print(f"stale: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print("Local Evidence MCP README boundary asset is current and valid XML.")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    print(f"wrote {OUTPUT.relative_to(ROOT)} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
