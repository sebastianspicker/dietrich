# Architecture

Dietrich is a modular local application with three use cases: assess a document, create an
editable working copy, and export password-recovery material. The source document is untrusted;
the final working copy is sensitive output.

```text
CLI / TUI / Python API
          |
          v
application use cases
          |
          +----> OOXML / PDF / legacy candidate writers
          +----> password recovery and local external tools
          |
          v
private artifact transaction -> validate -> single atomic publish
```

`domain/` contains only typed facts shared across these paths. `application/` owns sequencing and
policy. Format packages own document semantics and write unpublished candidates. `safety/` owns
bounded container access and final publication. Interaction adapters do not contain document
policy. Every application use case enforces typed assessment blockers before invoking a backend.
OOXML identity requires exactly one defining main part and is checked again immediately before
publication against the candidate's declared format.

The public compatibility boundary is intentionally small: the five functions exported from
`dietrich`, their public value/error types, the two console entry points, CLI flags and exit codes,
and documented JSON/result fields. Internal format functions are not compatibility facades.

New code belongs where its decision is made: document semantics in its format package,
cross-format workflow in `application/`, pure records in `domain/`, untrusted I/O limits and
publication in `safety/`, and rendering/input collection in CLI or TUI.
