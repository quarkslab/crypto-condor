"""Configuration for pytest."""

from crypto_condor.cli.config import set_logging


def pytest_configure(config):
    """Configuration for pytest."""
    # Set CLI logging to DEBUG.
    if config.option.log_debug:
        set_logging(1)
    else:
        set_logging(0)


def pytest_addoption(parser):
    """Additional options."""
    parser.addoption("--log-debug", action="store_true", default=False)
