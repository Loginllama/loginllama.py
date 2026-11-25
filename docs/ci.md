# CI gates

Every pull request runs, in `.github/workflows/cicd.yml`:

- `uv run ruff check .` (rules E, F, I, B; config in `pyproject.toml`)
- `uv run ruff format --check .`
- `uv run pytest`, which runs coverage and fails below 75% line coverage (`[tool.coverage.report] fail_under`)

The coverage table goes to the job summary. To run the same checks locally, use `uv sync --extra dev` and then the three commands above.

Design: https://github.com/loginllama/loginllama.py/issues/53
