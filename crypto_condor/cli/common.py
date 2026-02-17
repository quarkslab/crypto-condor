import typer

_compliance = typer.Option(
    "--compliance/--no-compliance", help="Use compliance test vectors."
)
_resilience = typer.Option(
    "--resilience/--no-resilience", help="Use resilience test vectors."
)
