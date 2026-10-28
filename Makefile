PYTHON ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)

.PHONY: lint test deb clean

lint:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m flake8 src tests
	$(PYTHON) -m mypy

test:
	$(PYTHON) -m pytest -q

deb:
	dpkg-buildpackage -us -uc -b

clean:
	rm -rf build .pybuild .pytest_cache .mypy_cache .ruff_cache src/*.egg-info
