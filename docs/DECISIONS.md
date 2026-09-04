# Decisions

- SQLite is supported for fast local tests; Docker uses PostgreSQL/pgvector as specified.
- Lexical cosine similarity is the zero-download fallback. The optional sentence-transformer path can be enabled in deployments with the model cached.
- Batch work uses FastAPI background tasks; no extra queue is required for the hackathon scope.
- Markdown export is included; PDF remains an optional conversion step.
