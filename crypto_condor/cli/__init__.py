"""CLI module for crypto-condor."""

from typer import rich_utils

# Hacky fix for dull help text on some terminals.
# https://github.com/tiangolo/typer/issues/437
# Update 08/09/2025: rich_utils is now lazy-loaded (see
# https://github.com/fastapi/typer/pull/1128) so we have to explicitly import it from
# typer. Override works the same way as before.
rich_utils.STYLE_HELPTEXT_FIRST_LINE = "bold"
rich_utils.STYLE_HELPTEXT = ""
