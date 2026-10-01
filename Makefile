.PHONY: install test lint clean

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -q

lint:
	python -m py_compile $$(find src -name "*.py")

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build dist *.egg-info
