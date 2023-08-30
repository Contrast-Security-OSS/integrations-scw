
from typing_extensions import Annotated

import typer

from rich.progress import track

from integrations_cli.auth import get_contrast_auth, get_contrast_api

from contrast_api.integration_secure_flag import SecureFlagIntegration
from contrast_api.integration_secure_flag import template as secure_flag_template
secure_flag_integration = SecureFlagIntegration(name="SecureFlag", template=secure_flag_template)

# Get the Rich instance
from . import console, CONFIG_FILE

cli = typer.Typer(no_args_is_help=True)


@cli.callback()
def main():
    """**Enable or remove the Secure Flag Integration**
    
    The Secure Flag integration adds a section to the 'How to Fix' information returned for each rule, which includes
    useful additional information from the Secure Flag platform for each vulnerability, including links to Secure Flag 
    resources and lab exercises.

    Please note that you will need a Secure Flag account and license to access lab exercises.
    """
    # First check that the auth file is ok before continuing
    contrast_auth = get_contrast_auth()


@cli.command()
def enable_for_rule(
        rule_name: Annotated[str, typer.Argument(help="The Rule to add the integration to")],
        confirm: Annotated[bool, typer.Option(help="Confirm the action and skip the prompt", show_default=False)]  = False,
):
    """Add the Secure Flag Integration to a single rule"""
    if not confirm:
        console.print()
        console.print(f"[yellow bold]You are about to add a SecureFlag Integration Block to the {rule_name} rule.")
        console.print("This will add text to the Recommendation section under 'How to Fix' for this rule.")
        console.print("The tool will attempt to keep any existing rule customizations.")
        
        typer.confirm("Are you sure you want to continue?", abort=True)

    contrast = get_contrast_api()

    rule = contrast.policy.get_details_for_rule(rule_name)
    
    result = secure_flag_integration.add_integration_block(rule)

    console.print(f"Added the SecureFlag Integration to the rule: {rule.name} rule :white_check_mark:")

    return result


@cli.command()
def enable_for_all():
    """Add the Secure Flag integration for all rules"""
    console.print()
    console.print(f"[yellow bold]You are about to add a SecureFlag Integration Block to all rules.")
    console.print("This will add text to the Recommendation section under 'How to Fix' for each rule.")
    console.print("The tool will attempt to keep any existing rule customizations.")
    
    typer.confirm("Are you sure you want to continue?", abort=True)

    console.print()
    console.print(f"[bold blue]Adding the Secure Flag Integration to all rules...")

    contrast = get_contrast_api()

    policy = contrast.policy.get_org_policy()

    for rule in track(policy.rules, description="[bold blue]Adding the Secure Flag Integration to all rules...", console=console):
        result = enable_for_rule(rule.get("name"), confirm=True)

    console.print()
    console.print(f"[green]Finished adding the SecureFlag Integration! :thumbs_up:")



@cli.command()
def remove_for_rule(
    rule_name: Annotated[str, typer.Argument(help="The Rule to remove the integration from")],
    confirm: Annotated[bool, typer.Option(help="Confirm the action and skip the prompt", show_default=False)]  = False,
):
    """Remove the Secure Flag integration from a single rule"""
    if not confirm:
        console.print()
        console.print(f"[yellow bold]You are about to remove the Secure Flag Integration Block to the {rule_name} rule.")
        console.print("This will remove the Recommendation section under 'How to Fix' for this rule.")
        console.print("The tool will attempt to keep any other rule customizations.")
    
        typer.confirm("Are you sure you want to continue?", abort=True)
    
    contrast = get_contrast_api()
    
    rule = contrast.policy.get_details_for_rule(rule_name)
    
    try:
        result = secure_flag_integration.remove_integration_block(rule)
        console.print(f"Removed the Secure Flag Integration from rule: {rule_name} :white_check_mark:")
    except Exception as err:
        console.print(f"[red bold]Failed to remove the Secure Flag Integration to the rule: {rule_name} rule :x:")
        console.print(err)


@cli.command()
def remove_for_all():
    """Remove the Secure Flag integration from all rules"""
    console.print()
    console.print(f"[yellow bold]You are about to remove the Secure Flag Integration Block from all rules.")
    console.print("This will remove the custom Recommendation section under 'How to Fix' for this rule.")
    console.print("The tool will attempt to keep any other rule customizations.")
    
    typer.confirm("Are you sure you want to continue?", abort=True)

    console.print()
    console.print("[bold yellow]Removing the Secure Flag integration form all rules... (this could take a minute)")

    contrast = get_contrast_api()

    org_policy = contrast.policy.get_org_policy()

    for rule in track(org_policy.rules, description="[bold yellow]Removing Secure Flag from all rules...", console=console):
        result = remove_for_rule(rule.get("name"), confirm=True)

    console.print()
    console.print("[green]Finished removing the Secure Flag integration from all rules! :thumbs_up:")
