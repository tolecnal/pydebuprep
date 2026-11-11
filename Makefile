PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: lint test coverage deb clean generated audit docs docs-serve

lint:
	$(PYTHON) -m ruff check src tests scripts tools
	$(PYTHON) -m ruff format --check src tests scripts tools
	$(PYTHON) -m mypy

# Tests run on every core (pytest-xdist). JOBS=0 runs them in one process, for debugging.
JOBS ?= auto

test:
	$(PYTHON) -m pytest -q -n $(JOBS)

# Branch coverage; fails below fail_under in pyproject.toml.
coverage:
	$(PYTHON) -m pytest -q -n $(JOBS) --cov --cov-report=term-missing

# Files generated from the code; tests fail if they are out of date.
generated:
	mkdir -p completions/bash completions/zsh examples
	PYTHONPATH=src $(PYTHON) -m pydebuprep completion bash > completions/bash/pydebuprep
	PYTHONPATH=src $(PYTHON) -m pydebuprep completion zsh > completions/zsh/_pydebuprep
	PYTHONPATH=src $(PYTHON) -c 'import sys; from pydebuprep.cleanup.completion import main; sys.exit(main(["bash"]))' > completions/bash/pydebuprep-cleanup
	PYTHONPATH=src $(PYTHON) -c 'import sys; from pydebuprep.cleanup.completion import main; sys.exit(main(["zsh"]))' > completions/zsh/_pydebuprep-cleanup
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
	$(DOCS_PYTHON) tools/docs_build.py
	$(DOCS_PYTHON) -m zensical build --strict -f build/zensical.yml

# Serves the expanded pages: run `make docs-serve` again after changing a page.
docs-serve:
	$(DOCS_PYTHON) tools/docs_build.py
	$(DOCS_PYTHON) -m zensical serve -f build/zensical.yml
