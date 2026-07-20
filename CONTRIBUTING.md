# Contributing to ICARUS

ICARUS is Beta, source-available software under
[PolyForm Noncommercial 1.0.0](LICENSE). Contributions are welcome for noncommercial
research and improvement. By submitting a contribution you agree it is licensed under
the same terms as the project.

## Development setup

```bash
git clone https://github.com/Indegosblade/icarus-framework
cd icarus-framework
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Before opening a pull request

CI runs the same gates on Linux, macOS, and Windows across Python 3.10–3.13. Run them
locally first:

```bash
pytest tests/ -q          # test suite
ruff check .              # lint
mypy icarus/              # type check
bandit -r icarus/ -c pyproject.toml   # security lint
```

All four must pass. New behavior needs test coverage; bug fixes should add a regression
test.

## Adding a parser

Parsers auto-register from `icarus/parsers/`. Each ships a YAML manifest validated by
JSON Schema at load time and must pass the 4-gate harness (golden output, idempotency,
schema conformance, zero-PII). Run `icarus parser test <name>` before submitting.

## Pull request process

1. Branch from `main`.
2. Keep the change focused; reference the issue it closes (`Closes #NN`).
3. Ensure the four gates above pass locally and in CI.
4. PRs are squash-merged. Write a clear, imperative commit subject.

## Security

Do not report security vulnerabilities through public issues or pull requests. See
[SECURITY.md](SECURITY.md).
