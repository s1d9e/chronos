.PHONY: install lint typecheck test probe demo clean

install:
	pip install -e ".[dev]"

lint:
	ruff check .

typecheck:
	mypy chronos/

test:
	pytest

probe:
	gcc -O0 -o /tmp/probe examples/behaviour_probe.c

demo: probe
	chronos run -- /tmp/probe

clean:
	rm -rf build dist *.egg-info .mypy_cache .pytest_cache .ruff_cache __pycache__ chronos/**/__pycache__
