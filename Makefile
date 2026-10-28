PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: lint test deb clean generated

lint:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m flake8 src tests
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q

# Files generated from the code; tests fail if they are out of date.
generated:
	mkdir -p completions/bash completions/zsh examples
	PYTHONPATH=src $(PYTHON) -m pydebuprep completion bash > completions/bash/pydebuprep
	PYTHONPATH=src $(PYTHON) -m pydebuprep completion zsh > completions/zsh/_pydebuprep
	PYTHONPATH=src $(PYTHON) -m pydebuprep example-config > examples/pydebuprep.conf

deb:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf build .pybuild .pytest_cache .mypy_cache .ruff_cache src/*.egg-info
