# Engineering log

## 2026-07-18

The prototype uses newline-delimited JSON-RPC over standard input and output.
It advertises five narrow tools and deliberately exposes no command execution.

Embedding caches contain content digests and numeric vectors, never source
text. Reads are sanitized before chunking so snippets inherit the same
redaction policy as direct reads.

