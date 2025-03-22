.PHONY: help setup lint test notebooks git-clean-ignored changelog log-change bump-version

VERSION_FILE := VERSION
CHANGELOG_FILE := CHANGELOG.md

help:
	echo ""
	echo "📦 Project Makefile – Available commands:"
	echo ""
	echo "  make setup               Create virtual environment and install dependencies"
	echo "  make lint                Run linter (ruff)"
	echo "  make test                Run unit tests (pytest)"
	echo "  make notebooks           Start Jupyter Lab"
	echo "  make git-clean-ignored   Remove tracked files now ignored by .gitignore"
	echo "  make log-change target=... desc=...    Log a change to the CHANGELOG"
	echo "  make bump-version        Bump patch version in VERSION and changelog"
	echo ""

setup:
	python3 -m venv .venv
	source .venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

lint:
	ruff src/ notebooks/

test:
	pytest

notebooks:
	jupyter lab

git-clean-ignored:
	git ls-files --cached --ignored --exclude-standard > .tmp_gitignored
	if [ -s .tmp_gitignored ]; then \
		cat .tmp_gitignored | xargs git rm --cached; \
		rm .tmp_gitignored; \
		echo "✅ Removed tracked files now ignored."; \
	else \
		echo "✅ Nothing to clean."; \
		rm .tmp_gitignored; \
	fi

log-change:
	@echo "📝 Logging change to $(CHANGELOG_FILE)..."
	@echo "" >> $(CHANGELOG_FILE)
	@echo "### [$(shell date +%Y-%m-%d)] - Auto Log Entry" >> $(CHANGELOG_FILE)
	@echo "- Target: $(target)" >> $(CHANGELOG_FILE)
	@echo "- Description: $(desc)" >> $(CHANGELOG_FILE)
	@echo "✅ Entry added."

bump-version:
	@echo "🔢 Bumping patch version..."
	@if [ ! -f $(VERSION_FILE) ]; then echo "0.1.0" > $(VERSION_FILE); fi
	@OLD_VERSION=$$(cat $(VERSION_FILE)); \
	NEW_VERSION=$$(echo $$OLD_VERSION | awk -F. '{$$NF += 1; print $$1"."$$2"."$$3}'); \
	echo $$NEW_VERSION > $(VERSION_FILE); \
	sed -i '' "0,/## \[.*\]/s//## [$$NEW_VERSION] - $$(date +%Y-%m-%d)/" $(CHANGELOG_FILE); \
	echo "🔖 Version bumped from $$OLD_VERSION to $$NEW_VERSION"
