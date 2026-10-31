PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: lint test coverage deb clean generated audit docs docs-serve

lint:
	$(PYTHON) -m ruff check src tests scripts tools
	$(PYTHON) -m ruff format --check src tests scripts tools
	$(PYTHON) -m flake8 src tests scripts tools
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q

# Branch coverage; fails below fail_under in pyproject.toml.
coverage:
	$(PYTHON) -m pytest -q --cov --cov-report=term-missing

# Files generated from the code; tests fail if they are out of date.
generated:
	mkdir -p completions/bash completions/zsh examples
	PYTHONPATH=src $(PYTHON) -m pydebuprep completion bash > completions/bash/pydebuprep
	PYTHONPATH=src $(PYTHON) -m pydebuprep completion zsh > completions/zsh/_pydebuprep
	PYTHONPATH=src $(PYTHON) -m pydebuprep example-config > examples/pydebuprep.conf
	mkdir -p schema
	PYTHONPATH=src $(PYTHON) -m pydebuprep.schema report > schema/report.schema.json
	PYTHONPATH=src $(PYTHON) -m pydebuprep.schema config > schema/config.schema.json

# Run as root with pydebuprep installed: proves report/snapshot change nothing else.
audit:
	scripts/readonly-audit.sh

deb:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf build site .pybuild .pytest_cache .mypy_cache .ruff_cache src/*.egg-info

# The documentation site; needs: pip install -r requirements-docs.txt (e.g. in .venv-docs)
DOCS_PYTHON ?= $(if $(wildcard .venv-docs/bin/python),.venv-docs/bin/python,python3)

docs:
	NO_MKDOCS_2_WARNING=1 $(DOCS_PYTHON) -m mkdocs build

docs-serve:
	NO_MKDOCS_2_WARNING=1 $(DOCS_PYTHON) -m mkdocs serve
