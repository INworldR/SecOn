# SecOn Project Guidelines

## Build/Lint/Test Commands
- `make setup` - Create virtual environment and install dependencies
- `make lint` - Run linter (ruff)
- `make test` - Run unit tests (pytest)
- `make test TESTPATH=path/to/test.py` - Run a single test
- `make notebooks` - Start Jupyter Lab

## Code Style Guidelines
- **Imports**: Standard library first, then third-party, then local
- **Formatting**: 4-space indentation, max line length 88 characters
- **Types**: Use type hints for function parameters and return values
- **Naming**: snake_case for variables/functions, CamelCase for classes
- **Error Handling**: Use try/except blocks with specific exceptions
- **Docstrings**: Use Python docstrings with Args and Returns sections
- **Comments**: Begin with # and a space, only for complex logic
- **String Formatting**: Use f-strings over .format() or %
- **Environment**: Python 3.12, managed with conda (environment.yml)

## Project Structure
- `/data/` - Raw and processed data
- `/src/` - Source code modules
- `/notebooks/` - Jupyter notebooks
- `/results/` - Output files, plots, reports
- `/docs/` - Documentation