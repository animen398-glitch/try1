"""core/document_providers — optional Document Intelligence providers.

Each provider runs an external/optional tool behind a thin, never-raising adapter
and normalises its output into our finding shapes (EXT-OSINT F2). Heavy or
license-encumbered tools (e.g. lift's 9B vision model) are run as subprocesses and
are NEVER imported into our process, so torch/vLLM never load here and nothing is
bundled into the .exe.
"""
