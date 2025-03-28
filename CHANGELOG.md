# 📄 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),  
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0] - 2025-03-29

### Added
- New `analyse_data_enhanced.py` script for advanced log analysis:
  - Detection of attack patterns and sophistication levels (LOW, MEDIUM, HIGH, APT)
  - APT (Advanced Persistent Threat) pattern identification using specialized heuristics
  - Attack grouping to identify campaigns based on time, targets, and techniques
  - Comprehensive JSON output format for integration with other security tools
  - Human-readable console summary for quick analysis
  - Auto-detection of newest JSON file in the data directory
  - Advanced JSON error handling with context display and repair options
  - New CLI options `--show-error-context` and `--truncate-json` for troubleshooting
  - Support for exporting analysis results to JSON for further processing

- New `fix_merged_json.py` utility script:
  - Specialized tool for repairing incorrectly merged JSON arrays
  - Multiple repair strategies for different types of JSON corruption
  - Handles common case of multiple arrays joined with `][`

### Added
- `README_analyse_enhanced.md` with detailed documentation for the enhanced analysis module
- Test script for verifying functionality of the enhanced analysis module

### Fixed
- JSON serialization error with `Timedelta` objects in analysis output

---

## [0.3.0] - 2025-03-28

### Added

- Enhanced `get_data.py` script with pagination support to retrieve large datasets:
  - New `--full-extract` flag to enable pagination beyond Elasticsearch's 10,000 document limit
  - `--batch-size` parameter to control pagination batch size
  - `--max-results` parameter to limit total number of results
  - Progress tracking during large extractions
  - Automatic fallback between pagination methods:
    - Point in Time (PIT) + search_after (primary method)
    - Plain search_after (first fallback)
    - from/size pagination (second fallback, limited to 10,000 results)

- Advanced OQL parsing with improved date filtering capabilities:
  - Support for date ranges with `@timestamp:[START TO END]` syntax
  - Support for comparison operators (`>=`, `>`, `<=`, `<`) with dates
  - Automatic date formatting for full-day ranges
  - Support for logical operators (`AND`, `OR`) in queries
  - Better handling of complex nested queries

### Changed

- Improved error handling in Elasticsearch requests
- Enhanced error messages for better troubleshooting
- Optimized export functionality for large datasets

---

## [0.2.0] - 2025-03-25

### Added

- Enhanced `get_data.py` script with advanced filtering capabilities:
  - Time-based filtering (`--hours`) to get logs from the last N hours
  - Program/service filtering (`--program`) to filter logs by service name
  - Priority filtering (`--priority`) to filter logs by syslog priority
  - Pattern searching (`--pattern`) to filter logs by regex patterns in messages
  - Onion Query Language support (`--oql`) for complex query syntax
  - Multiple output formats (default, JSON, YAML)
  - Support for aggregations through OQL (e.g., `groupby` operations)

### Changed

- Improved SSH tunnel handling in `get_data.py`
- Enhanced Elasticsearch query builder for more precise log filtering
- Log output preserves original format
- Fixed an issue where `--hours` parameter would still be limited to 100 results by default

---

## [0.1.0] - 2025-03-22

### Added

- Introduced initial `Makefile` with the following targets:
  - `make setup` – Create virtual environment and install dependencies
  - `make lint` – Run linter (`ruff`) on `src/` and `notebooks/`
  - `make test` – Run unit tests (pytest)
  - `make notebooks` – Start Jupyter Lab
  - `make git-clean-ignored` – Remove tracked files that are now ignored by `.gitignore`
  - `make help` – Show available commands with short descriptions

- `.gitignore` updated to exclude:
  - `data/`, `results/`, `notebooks/`
  - Python/venv/IDE-specific and common build artifacts

- Initial `CHANGELOG.md` following Keep a Changelog format

- Added `make log-change` target for automated changelog entries:
  - Usage: `make log-change target=setup desc="Initial setup of venv and deps"`

- Added `make bump-version` target to increment patch version
