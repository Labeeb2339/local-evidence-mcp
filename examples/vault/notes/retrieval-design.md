# Retrieval design

## Goal

Give an assistant access to a deliberately small evidence set instead of an
entire personal knowledge base.

## Boundary

Every readable file must match the policy allowlist. Absolute paths, traversal,
linked files, and excluded paths are rejected before content is returned.

## Ranking

Local embeddings improve semantic recall when the configured loopback service
is available. A deterministic lexical score keeps retrieval useful offline.

