"""Configuration module for crypto-condor."""

import logging

from rich.logging import RichHandler

from crypto_condor.primitives.common import Console

console = Console()


def set_logging(verbose_level: int = 0):
    """Set logging for the application.

    Args:
        verbose_level: The verbosity of the logs, corresponds to the count of '-v'
            options used in the CLI. *Does not* correspond to logging LEVELS.
    """
    FORMAT = "%(message)s"

    # no cover since testing logging is out of scope.
    match verbose_level:  # pragma: no cover
        case 0:
            level = logging.WARNING
            handler = RichHandler(
                console=console,
                level=logging.WARNING,
                show_time=False,
                show_level=True,
                show_path=False,
            )
        case 1:
            level = logging.INFO
            handler = RichHandler(
                console=console,
                level=logging.INFO,
                show_time=False,
                show_level=True,
                show_path=False,
            )
        case _:
            level = logging.DEBUG
            handler = RichHandler(console=console, level=logging.DEBUG, show_time=False)

    logging.basicConfig(level=level, format=FORMAT, force=True, handlers=[handler])
    logging.getLogger("crypto-condor").setLevel(level)
