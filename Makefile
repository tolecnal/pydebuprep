PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: lint test coverage deb clean generated audit

lint:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m flake8 src tests
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

# Run as root with pydebuprep installed: proves report/snapshot change nothing else.
audit:
	scripts/readonly-audit.sh

deb:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf build .pybuild .pytest_cache .mypy_cache .ruff_cache src/*.egg-info
