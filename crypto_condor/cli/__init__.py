"""CLI module for crypto-condor."""

import typer

# Hacky fix for dull help text on some terminals.
# https://github.com/tiangolo/typer/issues/437
typer.rich_utils.STYLE_HELPTEXT_FIRST_LINE = "bold"
typer.rich_utils.STYLE_HELPTEXT = ""
