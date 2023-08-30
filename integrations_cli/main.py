# Standard imports
from typing import Optional
from typing_extensions import Annotated
from pathlib import Path

# Import previously made Console
from . import console, CONFIG_FILE
from rich.traceback import install
from rich.table import Table, Column
from rich.live import Live
from rich.prompt import Prompt
from rich.progress import track
from rich.logging import RichHandler
from rich import box

# Import Contrast API
from contrast_api.contrast_api import ContrastAPIConfig, ContrastAPI
from contrast_api.request_handler import RequestHandler
from contrast_api.integrations_helper import Integration
from contrast_api.models import Rule

from integrations_cli.auth import get_contrast_auth, get_contrast_api
# Configure Typer CLI
import typer
import typer.rich_utils
typer.rich_utils._TERMINAL_WIDTH = typer.get_terminal_size().columns

install(console=console, theme="monokai", width=typer.rich_utils._TERMINAL_WIDTH, locals_max_string=typer.rich_utils._TERMINAL_WIDTH, locals_max_length=typer.rich_utils._TERMINAL_WIDTH)

# Create the base app typer
app = typer.Typer(rich_markup_mode="markdown",
                  no_args_is_help=True,
                  pretty_exceptions_enable=True,
                  context_settings={"help_option_names": ["-h", "--help"]},
                 )

import integrations_cli.auth as auth_cli
import integrations_cli.secure_code_warrior as scw_cli
import integrations_cli.secure_flag as sf_cli

# Add subcommands
app.add_typer(auth_cli.cli, name="auth", no_args_is_help=True)
app.add_typer(scw_cli.cli, name="secure-code-warrior", no_args_is_help=True, rich_help_panel="Learning Platform Integrations")
app.add_typer(sf_cli.cli, name="secure-flag", no_args_is_help=True, rich_help_panel="Learning Platform Integrations")


# Main CLI Callback and Help Text
@app.callback()
def main():
    """**The Contrast Security Integrations CLI**
    
    Extend and customize Contrast's default Assess policy for your organization. The Assess policy contains a set of 
    rules that Contrast uses to categorize vulnerabilities and provide relevant remediation advice, risk information, 
    and external references for each vulnerability. We provide a default policy which is based on industry standards 
    and best practices, but you can extend this to include your own advice that might be more specific to your 
    organization. 

    **Making customizations to rules**

    Add your own customizations to the Assess policy, to include your own recommendation, risk info or external links 
    for a given rule. See the built in help for more information on the options available for each command.

    ```sh
    contrast-integrations --help
    contrast-integrations update-rule --help
    ```

    **Integrate with Learning Platforms**

    You can also integrate your secure code learning platform with Contrast which will include links to relevant 
    training, videos, labs and resources for each vulnerability. Currently we support:
    - **Secure Code Warrior**
    - **Secure Flag**
    
    ```sh
    contrast-integrations secure-code-warrior --help
    contrast-integrations secure-flag --help
    ```

    **Example use cases:**     

    - Add an additional link to internal documentation on how to handle a particular vulnerability type.
    - Add a paragraph to the Risk section, detailing how a particular vulnerability affects your organization.
    """
    pass

@app.command(rich_help_panel="Basic Policy Enhancements")
def get_rule(rule_name: Annotated[str, typer.Argument(help="The Rule to get details for")]) -> Rule:
    """Get details for a single rule"""
    contrast = get_contrast_api()
    rule = contrast.policy.get_details_for_rule(rule_name=rule_name)
    console.print(rule)
    return rule


# TODO: implement severity level customization
@app.command(rich_help_panel="Basic Policy Enhancements")
def update_rule(
    rule_name: Annotated[str, typer.Argument(help="The Rule to get details for")],
    recommendation: Annotated[Optional[str], typer.Option(help="Custom Recommendation text to add to a rule")],
    risk: Annotated[Optional[str], typer.Option(help="Custom Risk text to add to a rule")] = None,
    ) -> Rule:
    """Update customizations for a single rule"""
    contrast = get_contrast_api()
    rule = contrast.policy.get_details_for_rule(rule_name=rule_name)
    console.print(rule)

    # TODO: Add validation for recommendation and risk

    response = rule.update(new_recommendation=recommendation, new_risk=risk)
    console.print(response)
    # return rule


@app.command(rich_help_panel="Basic Policy Enhancements")
def list_org_policy(details : Annotated[bool, typer.Option(help="Show details for each rule")] = False):
    """Get a list of the Policy Rules for the current organization"""
    contrast = get_contrast_api()

    with console.status("[bold green]Getting your organization policy...") as spinner:
        org_policy = contrast.policy.get_org_policy()

        if not details:
            table = Table("Title", "Name", "Description", title="Rules in your current org's policy:", title_justify="left", 
                        padding=(0,1), title_style="bold italic blue", box=box.ROUNDED)
        
            spinner.update(status="[bold green] Printing policy rules to table...")
        
            for rule in org_policy.rules:
                table.add_row(rule.get("title"), rule.get("name"), rule.get("description"))

            spinner.stop()

        else:
            table = Table(
                        Column("Title"), 
                        Column("Name"), 
                        Column("Description"),
                        Column("Custom Recommendation"),
                        Column("Custom Risk"), 
                        Column("Custom Likelihood"),
                        Column("Custom Confidence"), 
                        Column("Custom Impact"),
                        title="Rules in your current org's policy:", 
                        title_justify="left", 
                        padding=(0,1), 
                        title_style="bold italic blue", 
                        box=box.ROUNDED
                    )

            spinner.stop()

            for rule in track(org_policy.rules, description="[bold green] Getting details for each rule..."):
                policy_rule = contrast.policy.get_details_for_rule(rule_name=rule.get("name"))
                table.add_row(
                        policy_rule.title, 
                        policy_rule.name, 
                        policy_rule.description, 
                        "[yellow]True" if policy_rule.recommendation else "[dim]None", 
                        "[yellow]True" if policy_rule.risk else "[dim]None", 
                        f"[yellow]{policy_rule.likelihood_custom}" if policy_rule.likelihood_custom else "[dim]None",
                        f"[yellow]{policy_rule.impact_custom}" if policy_rule.impact_custom else "[dim]None",
                        f"[yellow]{policy_rule.confidence_level_custom}" if policy_rule.confidence_level_custom else "[dim]None",
                        style="dim" if not policy_rule.has_customizations else "",
                    )
            
        console.print(table)


@app.command(rich_help_panel="Basic Policy Enhancements")
def reset_rule(
    rule_name: Annotated[str, typer.Argument(help="The Rule to reset")],
    confirm: Annotated[bool, typer.Option(help="Confirm the action and skip the prompt", show_default=False)]  = False,
):
    """Reset the specified rule to default"""
    if not confirm:
        console.print()
        console.print(f"[red bold]You are about to RESET the {rule_name} rule for your organization.")
        console.print("This will remove all custom Recommendations, References, Risk and Severity Level overrides.")
        console.print("Please confirm this is what you want to do.")

        confirm = typer.confirm("Are you sure you want to continue?")

    if not confirm:
        console.print("Aborting...")
        return
    
    # console.print("[bold red]Resetting all rule customizations... (this could take a minute)")
    contrast = get_contrast_api()

    # table = Table("Rule Name", "Title", "Customizations?")
    
    try:
        result = contrast.policy.reset_rule(rule_name)
        console.print(f"Reset rule: {rule_name} :white_check_mark:")
    except Exception as err:
        console.print(f"[red bold]Failed to reset the {rule_name} rule :x:")
        console.print(err)



@app.command(rich_help_panel="Basic Policy Enhancements")
def reset_all_rules(rich_help_panel="Basic Policy Enhancements"):
    """Reset all rules to default"""
    console.print()
    console.print(f"[red bold]You are about to RESET ALL RULE CUSTOMIZATIONS for your organization.")
    console.print("This will remove all custom Recommendations, References, Risk and Severity Level overrides.")
    console.print("Please confirm this is what you want to do.")

    confirm = typer.confirm("Are you sure you want to continue?")

    if not confirm:
        console.print("Aborting...")
        return
    
    console.print()
    console.print("[bold red]Resetting all rule customizations... (this could take a minute)")

    contrast = get_contrast_api()

    org_policy = contrast.policy.get_org_policy()

    for rule in track(org_policy.rules, description="[bold red]Resetting all rules...", console=console):
        result = reset_rule(rule.get("name"), confirm=True)

    console.print()
    console.print(f"[green]Finished resetting all rules back to default! :thumbs_up:")


# Allow calling as a file or module
if __name__ == "__main__":
    app()
