"""darkmoon plugin: triage the findings file of a Darkmoon pentest scan."""


def register(ctx) -> None:
    # Imported here so the package can also be imported standalone (for example by a test runner).
    from . import schemas, tools

    ctx.register_tool(
        name="darkmoon_findings",
        toolset="darkmoon",
        schema=schemas.DARKMOON_FINDINGS,
        handler=tools.handle_darkmoon_findings,
        emoji="\U0001F6E1",
    )
