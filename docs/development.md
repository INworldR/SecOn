# Development Guidelines

This document outlines the development standards and best practices for contributing to the SecOn project. Following these guidelines ensures code quality, maintainability, and a consistent development experience across the project.

## Development Environment

### Setting Up the Development Environment

```bash
# Clone the repository
git clone git@github.com:INworldR/SecOn.git
cd SecOn

# Set up Python virtual environment
make setup

# Configure environment variables
cp conf/example.env conf/.env
# Edit .env file with your specific settings

# Run linter to verify environment
make lint

# Run tests to ensure everything is working
make test
```

### Required Tools

- **Python**: Version 3.12 or higher
- **Git**: For version control
- **Make**: For automation tasks
- **IDE**: Any Python-compatible IDE (VSCode, PyCharm recommended)
- **SSH Client**: For connecting to SecurityOnion
- **JupyterLab**: For interactive development and visualization

## Code Style Guidelines

### Python Style Guide

The SecOn project follows PEP 8 with some project-specific adaptations.

#### Basic Principles

- **Readability**: Code should be written for clarity and maintainability
- **Simplicity**: Keep it simple and focused
- **Documentation**: Code should be self-documenting, with comments where necessary
- **Testing**: All code should have appropriate tests

#### Style Specifics

1. **Indentation**: 4 spaces (no tabs)
2. **Line Length**: Maximum 88 characters
3. **Imports**:
   - Standard library imports first
   - Third-party imports second
   - Local application imports third
   - Separated by blank lines
   ```python
   # Good
   import os
   import sys
   
   import numpy as np
   import pandas as pd
   
   from src.utils import helper
   ```

4. **Naming Conventions**:
   - `snake_case` for variables, functions, and methods
   - `PascalCase` for classes
   - `UPPER_CASE` for constants
   ```python
   # Good
   MAX_CONNECTIONS = 100
   
   def calculate_average(values):
       pass
   
   class SecurityEvent:
       pass
   
   connection_pool = initialize_pool()
   ```

5. **String Formatting**: Use f-strings (since Python 3.6+)
   ```python
   # Good
   name = "World"
   greeting = f"Hello, {name}!"
   
   # Avoid
   greeting = "Hello, {}!".format(name)
   greeting = "Hello, %s!" % name
   ```

6. **Comments and Documentation**:
   - Docstrings for all modules, classes, and functions
   - Use Google-style docstrings
   ```python
   def analyze_attack(attack_data, sophistication_threshold=0.7):
       """
       Analyze attack data and classify by sophistication level.
       
       Args:
           attack_data: Dictionary containing attack information
           sophistication_threshold: Threshold for high sophistication (default: 0.7)
           
       Returns:
           Dictionary with analysis results including sophistication level
           
       Raises:
           ValueError: If attack_data is missing required fields
       """
       pass
   ```

7. **Error Handling**:
   - Use specific exceptions rather than catching all exceptions
   ```python
   # Good
   try:
       with open(filename, 'r') as f:
           data = json.load(f)
   except FileNotFoundError:
       logger.error(f"File not found: {filename}")
   except json.JSONDecodeError:
       logger.error(f"Invalid JSON in file: {filename}")
   
   # Avoid
   try:
       with open(filename, 'r') as f:
           data = json.load(f)
   except Exception as e:
       logger.error(f"Error: {e}")
   ```

8. **Type Hinting**: Use type hints for function parameters and return values
   ```python
   from typing import Dict, List, Optional, Any

   def analyze_logs(
       log_data: List[Dict[str, Any]],
       start_time: Optional[str] = None,
       end_time: Optional[str] = None
   ) -> Dict[str, Any]:
       """Analyze log data within the specified time range."""
       # Implementation
       return analysis_results
   ```

### Code Organization

#### Project Structure

```
SecOn/
├── data/           # Data directory (not tracked in Git)
├── notebooks/      # Jupyter notebooks
├── references/     # Reference materials
├── results/        # Analysis results (not tracked in Git)
├── src/            # Source code
│   ├── analysis/   # Analysis modules
│   ├── alerts/     # Alert management code
│   ├── dashboards/ # Dashboard configurations
│   ├── integration/# External system integrations
│   ├── utils/      # Utility functions
│   └── visualization/ # Visualization code
├── tests/          # Test code
├── conf/           # Configuration files
├── .env            # Environment variables (not tracked in Git)
├── Makefile        # Automation commands
└── README.md       # Project documentation
```

#### Module Structure

Each Python module should follow this structure:

```python
"""
Module docstring describing the purpose and functionality.
"""

# Standard library imports
import os
import sys
from datetime import datetime

# Third-party imports
import numpy as np
import pandas as pd

# Local application imports
from src.utils import helpers
from src.analysis.base import Analyzer

# Constants
MAX_RETRIES = 3
DEFAULT_TIMEOUT = 30

# Classes
class CustomAnalyzer(Analyzer):
    """Class docstring."""
    
    def __init__(self, config=None):
        """Initialize the analyzer."""
        super().__init__(config)
        # More initialization

    def analyze(self, data):
        """Implement analysis method."""
        # Implementation
        return results

# Functions
def helper_function(param1, param2):
    """Function docstring."""
    # Implementation
    return result

# Main execution (if applicable)
if __name__ == "__main__":
    # Code that runs when the module is executed directly
    main()
```

## Git Workflow

### Branching Strategy

The SecOn project uses a simplified Git Flow approach:

- `main`: Stable production code
- `dev`: Development branch for integration
- Feature branches: For new features and bug fixes

```bash
# Create a new feature branch from dev
git checkout dev
git pull
git checkout -b feature/my-new-feature

# Work on your feature...

# Keep your branch up to date with dev
git checkout dev
git pull
git checkout feature/my-new-feature
git merge dev

# When feature is complete
git push -u origin feature/my-new-feature
# Create a pull request to merge into dev
```

### Commit Guidelines

Follow these guidelines for commit messages:

- Use the imperative mood ("Add feature" not "Added feature")
- First line should be 50 characters or less
- Optionally followed by a blank line and a more detailed explanation
- Reference issue numbers when relevant

Example:
```
Add APT detection algorithm

Implement advanced persistent threat detection based on duration and
targeting patterns. This addresses the requirements in issue #42.
```

### Pull Request Process

1. Create a PR from your feature branch to `dev`
2. Ensure all tests pass and linting is clean
3. Request review from at least one team member
4. Update PR based on review feedback
5. Merge once approved

## Testing Guidelines

### Test Structure

- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test interactions between components
- **Functional Tests**: Test end-to-end functionality

Tests should be organized to mirror the structure of the source code:

```
tests/
├── analysis/
│   ├── test_attack_patterns.py
│   └── test_sophistication.py
├── alerts/
│   └── test_alert_processor.py
├── utils/
│   └── test_helpers.py
└── conftest.py
```

### Writing Tests

Use pytest for writing tests:

```python
# tests/analysis/test_sophistication.py
import pytest
from src.analysis.sophistication import determine_sophistication

def test_determine_sophistication_low():
    """Test low sophistication detection."""
    attack_data = {
        "duration": 60,  # 1 minute
        "count": 5,
        "target_count": 1
    }
    
    result = determine_sophistication(attack_data)
    assert result == "LOW"

def test_determine_sophistication_high():
    """Test high sophistication detection."""
    attack_data = {
        "duration": 3600,  # 1 hour
        "count": 1000,
        "target_count": 15,
        "sensitive_ports": [22, 3389]
    }
    
    result = determine_sophistication(attack_data)
    assert result == "HIGH"

@pytest.mark.parametrize("attack_data,expected", [
    ({"duration": 60, "count": 5, "target_count": 1}, "LOW"),
    ({"duration": 1800, "count": 50, "target_count": 5}, "MEDIUM"),
    ({"duration": 3600, "count": 1000, "target_count": 15}, "HIGH"),
])
def test_determine_sophistication_parametrized(attack_data, expected):
    """Test sophistication detection with parametrization."""
    result = determine_sophistication(attack_data)
    assert result == expected
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
make test TESTPATH=tests/analysis/test_sophistication.py

# Run specific test
make test TESTPATH=tests/analysis/test_sophistication.py::test_determine_sophistication_high
```

## Documentation Standards

### Code Documentation

- All modules, classes, and functions should have docstrings
- Docstrings should follow Google style
- Complex algorithms should have additional comments explaining the approach

Example:
```python
def detect_apt_patterns(logs, timespan=86400, min_events=5):
    """
    Detect Advanced Persistent Threat patterns in logs.
    
    This function analyzes log data to identify potential APT activity based
    on long duration, low volume, and specific targeting patterns.
    
    Args:
        logs: List of log entries to analyze
        timespan: Minimum timespan in seconds to consider for APT (default: 86400 - 1 day)
        min_events: Minimum number of events required (default: 5)
        
    Returns:
        List of dictionaries containing detected APT patterns with:
        - source_ip: Source IP of the potential APT
        - first_seen: First seen timestamp
        - last_seen: Last seen timestamp
        - duration: Duration in seconds
        - target_count: Number of unique targets
        - evidence: List of evidence points supporting the APT classification
        
    Example:
        >>> logs = get_logs_for_past_week()
        >>> apt_patterns = detect_apt_patterns(logs, timespan=604800)  # 1 week
        >>> for pattern in apt_patterns:
        ...     print(f"Potential APT from {pattern['source_ip']}, duration: {pattern['duration']}")
    """
```

### Project Documentation

- README.md: Project overview and quick start
- Installation and configuration guides
- Analysis documentation
- Alert system documentation
- Developer guidelines (this document)

## Performance Considerations

### General Principles

1. **Profile Before Optimizing**: Use profiling tools to identify bottlenecks
2. **Optimize Data Structures**: Choose appropriate data structures for operations
3. **Vectorize Operations**: Use NumPy/Pandas vectorized operations instead of loops
4. **Handle Large Datasets**: Process large data in chunks

### Performance Tips

```python
# Inefficient: Processing large data with loops
results = []
for log in large_log_data:
    if log["severity"] == "high":
        results.append(process_log(log))

# Efficient: Using pandas
df = pd.DataFrame(large_log_data)
high_severity = df[df["severity"] == "high"]
results = high_severity.apply(process_log, axis=1).tolist()
```

For large datasets, use chunking:
```python
def process_large_file(filename, chunk_size=10000):
    """Process a large JSON file in chunks."""
    results = []
    
    # Process in chunks
    with open(filename, 'r') as f:
        while True:
            chunk = list(itertools.islice(f, chunk_size))
            if not chunk:
                break
                
            # Process chunk
            processed = process_chunk(chunk)
            results.extend(processed)
            
    return results
```

## Security Best Practices

### Secure Coding

1. **Validate Inputs**: Always validate and sanitize user inputs
2. **Manage Secrets**: Never hardcode credentials or secrets
   ```python
   # Wrong
   api_key = "1234567890abcdef"
   
   # Right
   import os
   from dotenv import load_dotenv
   
   load_dotenv()
   api_key = os.getenv("API_KEY")
   
   if not api_key:
       raise EnvironmentError("API_KEY environment variable not set")
   ```

3. **Use Secure Dependencies**: Regularly update dependencies and review for vulnerabilities
4. **Handle Sensitive Data**: Be cautious when logging or storing sensitive data

### API Security

1. **Authentication**: Always use authentication for APIs
2. **Rate Limiting**: Implement rate limiting for APIs
3. **Input Validation**: Validate all API inputs
4. **HTTPS**: Always use HTTPS for API communication

## Continuous Integration

### GitHub Actions

The SecOn project uses GitHub Actions for continuous integration:

```yaml
# .github/workflows/test.yml
name: Test

on:
  push:
    branches: [ main, dev ]
  pull_request:
    branches: [ main, dev ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python 3.12
      uses: actions/setup-python@v2
      with:
        python-version: 3.12
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        if [ -f requirements.txt ]; then pip install -r requirements.txt; fi
    - name: Lint with ruff
      run: |
        pip install ruff
        ruff src
    - name: Test with pytest
      run: |
        pip install pytest
        pytest
```

## Development Tools

### Makefile Commands

The SecOn project includes a Makefile with common commands:

```bash
# Set up development environment
make setup

# Run linter
make lint

# Run tests
make test

# Run JupyterLab
make notebooks

# See all available commands
make help
```

### IDE Configuration

#### VS Code

Recommended VS Code settings (`.vscode/settings.json`):

```json
{
    "python.linting.enabled": true,
    "python.linting.ruffEnabled": true,
    "python.formatting.provider": "black",
    "python.formatting.blackArgs": [
        "--line-length", "88"
    ],
    "editor.formatOnSave": true,
    "editor.rulers": [88],
    "python.testing.pytestEnabled": true,
    "python.testing.unittestEnabled": false,
    "python.testing.nosetestsEnabled": false,
    "python.testing.pytestArgs": [
        "tests"
    ]
}
```

#### PyCharm

- Enable PEP 8 inspections
- Set max line length to 88
- Configure external tools for ruff and pytest

## Logging and Debugging

### Logging Guidelines

```python
import logging

# Configure logger for module
logger = logging.getLogger(__name__)

def process_data(data):
    """Process input data."""
    logger.debug("Processing data: %s", data[:100])
    
    try:
        # Process data
        result = do_processing(data)
        logger.info("Successfully processed %d records", len(data))
        return result
    except ValueError as e:
        logger.error("Value error during processing: %s", str(e))
        raise
    except Exception as e:
        logger.exception("Unexpected error during processing")
        raise
```

### Debugging Tips

1. Use logging for debugging information
2. Set up DEBUG level logging during development
3. Use breakpoints in your IDE
4. Implement verbose mode for detailed output

```python
def analyze_data(data, verbose=False):
    """Analyze data with optional verbose output."""
    if verbose:
        print(f"Analyzing {len(data)} records")
    
    # Analysis steps
    results = {}
    
    for step, func in ANALYSIS_STEPS.items():
        if verbose:
            print(f"Running step: {step}")
        results[step] = func(data)
        if verbose:
            print(f"Step results: {len(results[step])} items")
    
    return results
```

## Code Review Checklist

When reviewing code, check for:

1. **Functionality**: Does the code work as expected?
2. **Code Style**: Does the code follow project style guidelines?
3. **Testing**: Are there adequate tests?
4. **Documentation**: Is the code well-documented?
5. **Security**: Are there any security concerns?
6. **Performance**: Are there any performance issues?
7. **Error Handling**: Is error handling appropriate?
8. **Edge Cases**: Are edge cases handled?

## Changelog Management

The SecOn project uses a structured changelog format:

```
## [0.3.0] - 2025-03-28

### Added
- Enhanced `get_data.py` script with pagination support
- Advanced OQL parsing with improved date filtering

### Changed
- Improved error handling in Elasticsearch requests
- Enhanced error messages for better troubleshooting

### Fixed
- JSON serialization error with `Timedelta` objects
```

To add a changelog entry:

```bash
make log-change target=analysis desc="Added advanced APT detection algorithm"
```

## Version Management

The SecOn project follows semantic versioning:

- MAJOR version for incompatible API changes
- MINOR version for new functionality in a backward compatible manner
- PATCH version for backward compatible bug fixes

To bump the version:

```bash
make bump-version
# or for specific version types:
make bump-major
make bump-minor
make bump-patch
```

## Collaboration Guidelines

### Communication Channels

- GitHub Issues: For bug reports and feature requests
- Pull Requests: For code review and discussion
- Project Wiki: For long-form documentation
- Team Chat: For quick questions and discussions

### Issue Management

1. **Create Descriptive Issues**: Include enough detail to understand the issue
2. **Use Labels**: Categorize issues with appropriate labels
3. **Assign Issues**: Assign issues to team members
4. **Track Progress**: Update issues with progress

### Pull Request Best Practices

1. **Reference Issues**: Link PRs to related issues
2. **Descriptive PR Titles**: Clearly describe what the PR does
3. **Include Context**: Provide background and motivation
4. **Keep PRs Focused**: One logical change per PR
5. **Review Your Own Code**: Self-review before requesting reviews

## Next Steps

Now that you understand the development guidelines, you can:

1. Set up your development environment
2. Pick an issue to work on
3. Create a feature branch
4. Implement your changes
5. Submit a pull request

For specific guidance on implementing certain features, refer to the following resources:

- [Analysis Scripts Guide](analysis_scripts.md)
- [Alert Configuration Guide](alerts.md)
- [SecurityOnion Integration Guide](configuration.md)

---

This development guide is part of the SecOn project documentation. For any questions or issues specific to the project implementation, contact the project lead.
