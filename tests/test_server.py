from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from local_evidence_mcp import server


class FailingEmbedder:
    def embed(self, text: str) -> list[float]:
        raise RuntimeError("offline")


class TinyEmbedder:
    def embed(self, text: str) -> list[float]:
        folded = text.casefold()
        return [
            float(folded.count("retrieval") + 1),
            float(folded.count("evidence") + 1),
            float(folded.count("local") + 1),
        ]


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temporary.name)
        self.root = self.workspace / "vault"
        (self.root / "notes").mkdir(parents=True)
        (self.root / "private").mkdir()
        (self.root / "writeups").mkdir()
        (self.root / "notes" / "overview.md").write_text(
            "# Retrieval\n\nLocal evidence retrieval uses a small allowlist.\n",
            encoding="utf-8",
        )
        (self.root / "notes" / "ranking.md").write_text(
            "# Ranking\n\nSemantic ranking has a deterministic lexical fallback.\n",
            encoding="utf-8",
        )
        (self.root / "notes" / "ignored.txt").write_text(
            "not Markdown", encoding="utf-8"
        )
        (self.root / "private" / "hidden.md").write_text(
            "# Hidden\n\nThis must stay private.\n", encoding="utf-8"
        )
        (self.root / "lessons.md").write_text(
            "# Lessons\n", encoding="utf-8"
        )
        self.policy = {
            "version": 1,
            "embeddings": {
                "enabled": True,
                "provider": "ollama",
                "endpoint": "http://127.0.0.1:11434/api/embeddings",
                "model": "tiny-test-model",
                "timeout_seconds": 0.1,
            },
            "read": {
                "files": ["lessons.md"],
                "globs": ["notes/*.md", "writeups/*.md", "private/*.md"],
            },
            "excluded": ["private/*"],
            "write": {
                "create_only_directory": "writeups",
                "append_only_file": "lessons.md",
            },
            "limits": {
                "max_read_bytes": 4096,
                "max_search_results": 8,
                "max_write_bytes": 16384,
                "max_index_files": 20,
                "max_chunk_characters": 600,
            },
        }
        self.policy_path = self.workspace / "policy.example.json"
        self._write_policy()
        self.cache_path = self.workspace / ".cache" / "embeddings.json"
        self.store = server.EvidenceStore(
            self.root,
            self.policy_path,
            self.cache_path,
            embedder=FailingEmbedder(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_policy(self) -> None:
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")

    @staticmethod
    def _secret_assignment() -> str:
        return "pass" + "word = " + "example-value-123456"

    @staticmethod
    def _raw_flag() -> str:
        return "FLAG" + "{" + "example_only" + "}"

    @staticmethod
    def valid_note() -> dict[str, object]:
        return {
            "date": "2026-07-18",
            "slug": "retrieval-decision",
            "title": "Retrieval decision",
            "summary": "The evidence set remains intentionally small.",
            "evidence": "Two allowlisted notes were inspected.",
            "decision": "Keep lexical fallback enabled.",
            "next_actions": ["Review the policy", "Run the test suite"],
            "tags": ["rag", "mcp"],
        }

    def test_allowlist_excludes_private_and_non_markdown_files(self) -> None:
        self.assertEqual(
            self.store.allowed_files(),
            ["lessons.md", "notes/overview.md", "notes/ranking.md"],
        )
        with self.assertRaisesRegex(server.EvidenceStoreError, "not allowlisted"):
            self.store.read("private/hidden.md")
        with self.assertRaisesRegex(server.EvidenceStoreError, "not allowlisted"):
            self.store.read("notes/ignored.txt")

    def test_paths_reject_absolute_traversal_wildcards_and_streams(self) -> None:
        invalid = [
            "../outside.md",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "notes/*.md",
            "notes/overview.md:stream",
        ]
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(server.EvidenceStoreError):
                    self.store.read(value)

    def test_read_redacts_credentials_and_raw_flags(self) -> None:
        target = self.root / "notes" / "sensitive.md"
        target.write_text(
            "# Example\n\n"
            + self._secret_assignment()
            + "\n"
            + self._raw_flag()
            + "\n",
            encoding="utf-8",
        )
        result = self.store.read("notes/sensitive.md")
        self.assertEqual(result["redactions"], 2)
        self.assertNotIn("example-value", result["content"])
        self.assertNotIn("example_only", result["content"])
        self.assertIn("REDACTED", result["content"])

    def test_large_file_is_rejected(self) -> None:
        target = self.root / "notes" / "large.md"
        target.write_text("x" * 5000, encoding="utf-8")
        with self.assertRaisesRegex(server.EvidenceStoreError, "size limit"):
            self.store.read("notes/large.md")

    def test_lexical_search_is_deterministic_fallback(self) -> None:
        first = self.store.search("semantic fallback", 2)
        second = self.store.search("semantic fallback", 2)
        self.assertEqual(first["mode"], "lexical")
        self.assertEqual(first["results"], second["results"])
        self.assertEqual(first["results"][0]["relative_path"], "notes/ranking.md")
        self.assertIn("lexical fallback", first["results"][0]["snippet"])

    def test_semantic_search_cache_contains_vectors_not_plaintext(self) -> None:
        store = server.EvidenceStore(
            self.root,
            self.policy_path,
            self.cache_path,
            embedder=TinyEmbedder(),
        )
        result = store.search("local evidence retrieval", 3)
        self.assertEqual(result["mode"], "semantic+lexical")
        self.assertTrue(result["results"])
        cache = self.cache_path.read_text(encoding="utf-8")
        self.assertNotIn("Local evidence retrieval", cache)
        parsed = json.loads(cache)
        self.assertEqual(parsed["model"], "tiny-test-model")
        self.assertTrue(parsed["vectors"])

    def test_search_rejects_sensitive_query(self) -> None:
        with self.assertRaisesRegex(server.EvidenceStoreError, "query rejected"):
            self.store.search(self._secret_assignment())
        with self.assertRaisesRegex(server.EvidenceStoreError, "query rejected"):
            self.store.search(self._raw_flag())

    def test_create_note_is_create_only(self) -> None:
        result = self.store.create_note(self.valid_note())
        self.assertEqual(result["mode"], "create-only")
        target = self.root / str(result["created"])
        content = target.read_text(encoding="utf-8")
        self.assertIn("# Retrieval decision", content)
        self.assertIn("created_by: local-evidence-mcp", content)
        self.assertIn(str(result["created"]), self.store.allowed_files())
        self.assertEqual(
            self.store.search("retrieval decision", 1)["results"][0]["relative_path"],
            str(result["created"]),
        )
        with self.assertRaisesRegex(server.EvidenceStoreError, "overwrite"):
            self.store.create_note(self.valid_note())

    def test_create_note_rejects_unknown_fields(self) -> None:
        arguments = self.valid_note()
        arguments["destination"] = "somewhere-else"
        with self.assertRaisesRegex(server.EvidenceStoreError, "unexpected fields"):
            self.store.create_note(arguments)

    def test_writes_reject_credentials_and_raw_flags(self) -> None:
        credential = self.valid_note()
        credential["evidence"] = self._secret_assignment()
        with self.assertRaisesRegex(server.EvidenceStoreError, "write rejected"):
            self.store.create_note(credential)

        lesson = {
            "subject": "Review",
            "lesson": self._raw_flag(),
            "verified_evidence": "A test assertion passed.",
        }
        with self.assertRaisesRegex(server.EvidenceStoreError, "write rejected"):
            self.store.append_lesson(lesson)

    def test_append_lesson_preserves_existing_content(self) -> None:
        destination = self.root / "lessons.md"
        original = destination.read_text(encoding="utf-8")
        result = self.store.append_lesson(
            {
                "subject": "Ranking",
                "lesson": "Keep a deterministic fallback.",
                "verified_evidence": "The offline search test passed.",
                "source_refs": ["notes/ranking.md"],
            }
        )
        content = destination.read_text(encoding="utf-8")
        self.assertEqual(result["mode"], "append-only")
        self.assertTrue(content.startswith(original))
        self.assertIn("Keep a deterministic fallback", content)

    def test_invalid_remote_embedding_endpoint_is_rejected(self) -> None:
        self.policy["embeddings"]["endpoint"] = "https://example.com/api/embed"
        self._write_policy()
        with self.assertRaisesRegex(server.EvidenceStoreError, "loopback"):
            server.EvidenceStore(self.root, self.policy_path, self.cache_path)

    def test_disabled_embeddings_do_not_create_a_network_client(self) -> None:
        self.policy["embeddings"]["enabled"] = False
        self._write_policy()
        store = server.EvidenceStore(self.root, self.policy_path, self.cache_path)
        result = store.search("local retrieval")
        self.assertIsNone(store.embedder)
        self.assertEqual(result["mode"], "lexical")

    def test_linked_files_are_not_indexed(self) -> None:
        outside = self.workspace / "outside.md"
        outside.write_text("# Outside\n\nDo not index this.\n", encoding="utf-8")
        link = self.root / "notes" / "linked.md"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlinks unavailable: {exc}")
        self.assertNotIn("notes/linked.md", self.store.allowed_files())
        with self.assertRaisesRegex(server.EvidenceStoreError, "linked"):
            self.store.read("notes/linked.md")

    def test_status_is_explicit_about_absent_capabilities(self) -> None:
        status = self.store.status()
        self.assertEqual(status["execution_capabilities"], [])
        self.assertIn("shell", status["explicitly_absent"])
        self.assertEqual(status["write_policy"]["create_only"], "writeups")


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        workspace = Path(self.temporary.name)
        self.root = workspace / "vault"
        (self.root / "notes").mkdir(parents=True)
        (self.root / "writeups").mkdir()
        (self.root / "notes" / "one.md").write_text(
            "# One\n\nUseful evidence.\n", encoding="utf-8"
        )
        (self.root / "lessons.md").write_text("# Lessons\n", encoding="utf-8")
        policy = {
            "read": {"files": ["lessons.md"], "globs": ["notes/*.md"]},
            "write": {
                "create_only_directory": "writeups",
                "append_only_file": "lessons.md",
            },
            "embeddings": {"enabled": False},
            "limits": {},
        }
        policy_path = workspace / "policy.example.json"
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        self.store = server.EvidenceStore(
            self.root, policy_path, workspace / "cache.json"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_initialize_and_tool_inventory(self) -> None:
        initialized = server.handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
        )
        self.assertEqual(initialized["result"]["protocolVersion"], "2025-06-18")
        listed = server.handle_request(
            self.store,
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        )
        names = {item["name"] for item in listed["result"]["tools"]}
        self.assertEqual(
            names,
            {
                "evidence_status",
                "evidence_search",
                "evidence_read",
                "evidence_create_note",
                "evidence_append_lesson",
            },
        )
        self.assertFalse(any("shell" in name for name in names))

    def test_tool_policy_error_is_returned_as_mcp_tool_error(self) -> None:
        response = server.handle_request(
            self.store,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "evidence_read",
                    "arguments": {"relative_path": "../outside.md"},
                },
            },
        )
        result = response["result"]
        self.assertTrue(result["isError"])
        self.assertNotIn("structuredContent", result)

    def test_invalid_request_and_unknown_method_use_jsonrpc_errors(self) -> None:
        invalid = server.handle_request(
            self.store, {"id": 1, "method": "ping"}
        )
        self.assertEqual(invalid["error"]["code"], -32600)
        unknown = server.handle_request(
            self.store,
            {"jsonrpc": "2.0", "id": 2, "method": "resources/list"},
        )
        self.assertEqual(unknown["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
