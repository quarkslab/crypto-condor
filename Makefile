VECTORS_DIR := crypto_condor/vectors

_PROTO_NAMES := $(shell find $(VECTORS_DIR) -name '*.proto' -printf "%f\n")
PROTO_NAMES := $(_PROTO_NAMES:%.proto=%)

PROTO_FILES := $(shell find crypto_condor -name '*.proto')

PB2_FILES := $(PROTO_FILES:%.proto=%_pb2.py)

# PROTO_FILES := $(PROTO_NAMES:%.proto=$(VECTORS_DIR)/_%/%.proto)
# PB2_FILES := $(PROTO_NAMES:%.proto=$(VECTORS_DIR)/_%/%_pb2.py)

DATE := $(shell date '+%Y.%m.%d')

default: help

.PHONY: help
help: # Show help for each of the Makefile recipes.
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m:$$(echo $$l | cut -f 2- -d'#')\n"; done

all: lint type-check coverage docs doctest

bump: # Bump the version to today.
	@echo "[+] Bump package version"
	@poetry version $(DATE)
	@echo "[+] Add new version to documentation tags"
	@grep -q $(DATE) docs/Makefile || sed -i "s/VERSIONS = main/VERSIONS = main $(DATE)/" docs/Makefile
	@echo "[+] Commit pyproject and docs/Makefile"
	@git add pyproject.toml docs/Makefile && git commit -m "Version $(DATE)"
	@echo "[+] Create git tag"
	@git tag -a $(DATE) -m "Version $(DATE)"

.PHONY: import-nist-vectors
import-nist-vectors: # Serialize NIST test vectors with protobuf.
import-nist-vectors: $(PROTO_FILES:%.proto=%.imported)

%.imported: %_import.py %_pb2.py
	@NAME=`dirname $@`; echo "[+] Importing NIST $$NAME test vectors"
	@python $<

compile-primitives: # Compile primitives written in C.
	@echo "[+] Compiling primitives"
	cd crypto_condor/primitives && $(MAKE) all -j4
	@echo

compile-primitives-ci: # Compile primitives written in C.
	@echo "[+] Compiling primitives (CI)"
	sudo apt-get install -y --no-install-recommends pandoc gcc
	cd crypto_condor/primitives && $(MAKE) all -j4
	@echo

copy-guides: # Copy guides from the docs for the method command.
	@echo "[+] Copying guides from the documentation"
	python utils/copy_guides.py
	@echo

copy-contributing: # Copy CONTRIBUTING from the docs to the root of the repo.
	@echo "[+] Copying CONTRIBUTING"
	cp docs/source/development/CONTRIBUTING.md .
	@echo

# To ensure the latest version is used for e.g. testing.
install: # Install using poetry.
	@echo "[+] Installing with poetry"
	poetry install --with=dev,docs
	@echo

ci-setup: # Basic commands to run before the other CI targets.
ci-setup:
	@echo "[+] Setup CI"
	export PYTHONDONTWRITEBYTECODE=1
	python --version
	python -m pip --version
	python -m pip install poetry
	poetry --version
	POETRY_VIRTUALENVS_IN_PROJECT=1 poetry install --with=dev,docs

init: # Common requirements for several targets.
init: install import-nist-vectors compile-primitives copy-guides copy-contributing

init-ci: # Common requirements before other CI targets.
init-ci: ci-setup import-nist-vectors copy-guides copy-contributing

lint: # Format with black and lint with ruff.
	@echo "[+] Linting"
	black --check .
	ruff check .

lint-ci: # Format with black, lint with ruff, generate report for CI.
lint-ci: init-ci
	@echo "[+] Linting (CI)"
	poetry run black --check .
	poetry run ruff check --output-format=github .

type-check: # Run mypy.
	@echo "[+] Type checking"
	mypy --config-file pyproject.toml .

type-check-ci: # Run mypy, generate report for CI.
type-check-ci: init-ci
	@echo "[+] Type checking (CI)"
	poetry run mypy --config-file pyproject.toml --junit-xml mypy.xml .

doctest: # Run doctest
doctest: init
	$(MAKE) -C docs doctest

doctest-ci: # Run doctest
doctest-ci: init-ci
	sudo apt-get install -y --no-install-recommends pandoc
	. .venv/bin/activate && $(MAKE) -C docs doctest

test: # Run pytest.
test: init
	@echo "[+] Testing"
	pytest -n auto -v tests/ -x

coverage: # Run coverage, generate HTML report.
coverage: init
	@echo "[+] Testing and checking coverage"
	pytest --cov="crypto_condor" --cov-report html --numprocesses=auto tests/

coverage-ci: # Run coverage, generate JUnit test report and XML coverage report.
coverage-ci: init-ci compile-primitives-ci
	@echo "[+] Testing and checking coverage (CI)"
	poetry run pytest --verbose --junitxml=junit/test-results.xml --cov="crypto_condor" --cov-report=xml --numprocesses=auto --dist worksteal tests/
# Print coverage report so that CI picks up stats
	poetry run coverage report

# Separate build target to fully build locally.
build: # Build the package.
build: init
	@echo "[+] Building package"
	poetry build

# This is redundant since publish-ci also builds the package, but we use this to check
# for building errors before trying to publish.
build-ci: # Build the package in the CI.
build-ci: init-ci compile-primitives-ci
	@echo "[+] Building package (CI)"
# Ensure that the tag and version match to avoid pushing a package without
# the corresponding documentation.
	. .venv/bin/activate && python utils/check_tag_and_version.py
	poetry build

publish-ci: # Publish package using the CI pipeline.
publish-ci: init
	@echo "[+] Publishing package (CI)"
	@poetry config pypi-token.pypi $(PYPI_TOKEN)
	@poetry publish -v --build

compile-proto: # Compile .proto files and prints current protoc version.
compile-proto: $(PB2_FILES)
	@protoc_version=`protoc --version`; echo "Protoc version: $$protoc_version"

%_pb2.py: %.proto
	@echo "[+] Recompiling $<"
	@protoc -I=$(VECTORS_DIR) --python_out=$(VECTORS_DIR) --mypy_out=$(VECTORS_DIR) $<

# This should only be called on main since the published docs are based on that
# branch.
pages-ci: # Build the documentation for GitLab Pages.
pages-ci: init-ci
	@echo "[+] Building all docs"
	sudo apt-get install -y --no-install-recommends pandoc
	. .venv/bin/activate && $(MAKE) -C docs all-versions
	cp docs/source/_static/redirect-index.html docs/build/public/index.html
# Rename docs from main to devel.
	mv docs/build/public/main docs/build/public/devel
# Move latest tag to latest.
	-LATEST_TAG="$(shell git describe --tags --abbrev=0 --exclude='*rc[0-9]')"; cp -R docs/build/public/$$LATEST_TAG docs/build/public/latest

.PHONY: docs
docs: # Build the documentation
docs: install
	$(MAKE) -C docs html

docs-ci: # Build the documentation
docs-ci: init-ci
	sudo apt-get install -y --no-install-recommends pandoc
	. .venv/bin/activate && $(MAKE) -C docs html

livedocs: # Build the documentation with live reload.
livedocs: install
	$(MAKE) -C docs livehtml

