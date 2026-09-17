install:
	pip install -r requirements.txt

fetch:
	python -m leancert.cli fetch-datasets

build-traces:
	python -m leancert.cli build-traces-from-datasets

test:
	pytest

validate:
	python -m leancert.cli validate-dir traces

experiment:
	python -m leancert.cli run-experiment traces --fetch --build-traces --repeat 5

lean:
	cd lean && lake build

