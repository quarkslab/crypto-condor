# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?= -W
SPHINXBUILD   ?= sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

PORT ?= 8000

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

VERSIONS = main 2025.03.13 2025.03.12 2025.02.07 2025.01.31 2024.09.24 2024.08.23 2024.08.19 2024.08.03 2024.07.03 2024.06.12

all-versions: $(VERSIONS)
	git checkout main
	@echo "[docs] Finished build"

$(VERSIONS):
	@echo "[docs] Building docs for $@"
	latest_tag="$(shell git describe --tags --abbrev=0 --exclude='*rc[0-9]')";\
	latest_commit="$(shell git rev-parse --short HEAD)";\
	git checkout $@;\
	$(SPHINXBUILD) "$(SOURCEDIR)" "$(BUILDDIR)/public/$@" -A latest_tag=$$latest_tag -A latest_commit=$$latest_commit -A versions="$(VERSIONS)"

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

livehtml:
	sphinx-autobuild "$(SOURCEDIR)" "$(BUILDDIR)/livehtml" $(SPHINXOPTS) $(O) \
		--port "$(PORT)" \
		--watch ../crypto_condor \
		--watch ../tests \
		--ignore *.dat
