PYTHON ?= python

.PHONY: test quick experiments figures all clean

test:
	$(PYTHON) -m pytest -q

quick:
	$(PYTHON) scripts/run_experiments.py --quick --output results_quick

experiments:
	$(PYTHON) scripts/run_experiments.py --output results

figures:
	$(PYTHON) scripts/make_figures.py --results results --output figures

all: test experiments figures

clean:
	rm -rf .pytest_cache results_quick
	find src tests scripts -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find src tests scripts -type f -name '*.py[co]' -delete 2>/dev/null || true
