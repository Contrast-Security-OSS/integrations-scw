
from typing import Optional
from typing_extensions import Annotated
from pathlib import Path

import typer

from . import console, CONFIG_DIR, CONFIG_FILE
from rich.table import Table, Column
from rich import box

from contrast_api.contrast_api import ContrastAPIConfig, ContrastAPI
from contrast_api.request_handler import RequestHandlerException

import logging
logger = logging.getLogger(__name__)

# AUTH MODULE
cli = typer.Typer()

@cli.callback()
def main():
    """**Manage authentication with the Contrast API and switch between organizations.**

    **Authenticate**
    All users can use the `auth init` command to authenticate to the Contrast API. This command will ask you for your 
    Contrast API keys, test the connection with these credentials and then save them to a config file for future use. 

    You can run `auth init` again to reset these credentials. 

    **Test authentication**
    All users can test their current auth settings using the `auth test` command. This will also return your current 
    admin level for the current org. 

    **Switch active organization**
    SuperAdmin users can switch between organizations from their profile using the `set-profile` command, allowing 
    them to run the CLI tool against the other orgs.
    """
        

@cli.command()
def init(
    api_key: Annotated[
        str, 
        typer.Option(
                help="Your Contrast User API Key", 
                prompt="What is your Contrast User API-Key?"
            )],
    auth_header: Annotated[
        str, 
        typer.Option(
                help="Your Contrast User Auth Header", 
                prompt="What is your Contrast User Auth-Header?"
            )],
    teamserver_url: Annotated[
        str, 
        typer.Option(
                help="Your Contrast TeamServer URL", 
                prompt="What is your Contrast TeamServer URL?"
            )] = "https://eval.contrastsecurity.com/Contrast",
):
    """**Initialize the CLI tool with your Contrast API credentials.**
    
    Takes your Contrast API keys as arguments or prompts you for them, tests them by attempting a 
    request to the API, and then saves them to a config file for further use.

    This file is saved to a sensible config location for each operating system using `typer.get_app_dir()`.

    To find your Contrast API Keys, please log in to the Contrast Platform (usually https://eval.contrastsecurity.com 
    or https://app.contrastsecurity.com) and navigate to `User Settings` -> `Your Keys`.
    """
    console.print()
    console.print("[bold blue]Initializing the Integrations CLI with your Contrast auth credentials")
    
    try: 
        contrast_api_config = ContrastAPIConfig(
                                teamserver_url=teamserver_url,
                                api_key=api_key,
                                auth_header=auth_header,
                            )
        # First create the directory
        Path(CONFIG_DIR).mkdir(parents=True, exist_ok=True)
        # Now write the file to that directory
        contrast_api_config.to_yaml_file(CONFIG_FILE)
    except Exception as err:
        console.print(f"[red bold]Could not initialize ContrastAPIConfig: {err}")
        raise Exception(err)
    
    try:
        extra_details = test()
        if extra_details.get('is_superadmin'):
            contrast_api_config.is_superadmin = True 
        
        contrast_api_config.set_default_profile(
            org_name=extra_details.get("default_org_name"), 
            org_uuid=extra_details.get("default_org_uuid"), 
            api_key=contrast_api_config.api_key, 
            config_file=CONFIG_FILE
        )

        console.print(f"Successfully initialized ContrastAPIConfig and saved to: {CONFIG_FILE}")
        console.print(contrast_api_config)
    except RequestHandlerException as err:
        console.print(f"[red bold]Something is wrong with your supplied credentials! Please try again.")
        raise err
    except Exception as err:
        raise typer.Exit()

    

@cli.command()
def test():
    """Test your current auth by making a request to the Contrast API"""
    # First check that the auth file is ok before continuing
    # contrast_auth = get_contrast_auth()
    console.print()
    console.print("[bold blue]Testing your current Contrast auth credentials by making requests to the Contrast API")

    try: 
        contrast_auth = get_contrast_auth()
        console.log(f"Successfully loaded config from file '{CONFIG_FILE}'")
        console.log(contrast_auth)
    except Exception as err:
        raise err

    contrast = get_contrast_api()

    with console.status("[bold green]Authenticating to Contrast API..."):
        try: 
            user_profile = contrast.profile.get_profile()

            console.print()    
            console.print("[green]Successfully authenticated to Contrast API")
            console.print(f"\t - Welcome {user_profile.first_name} {user_profile.last_name}!")

            if user_profile.superadmin_role:
                console.print(f"\t - You are a super admin! You can run this CLI tool for other orgs as long as you have ADMIN or RULES_ADMIN roles!")
            
            default_org = contrast.profile.get_default_org_from_profile()
            console.print(f"\t - Your default org is '{default_org.name}' ({default_org.organization_uuid})")
            console.print(f"\t - You {'have' if any(role in ['ROLE_ADMIN', 'ROLE_RULES_ADMIN'] for role in default_org.roles) else 'DO NOT'} ADMIN or RULES_ADMIN for the '{default_org.name}' org ")

            current_user_profile_orgs = contrast.profile.get_organizations_in_profile()

            table = Table(
                        Column("Organization Name", style="repr.str"), 
                        Column("Organization UUID", style="repr.uuid"), 
                        title="Organizations in your current profile:", 
                        leading=1, padding=(0,3), title_style="bold italic blue", box=box.ROUNDED)
            for org in current_user_profile_orgs:
                table.add_row(org.name, org.organization_uuid)

            console.print()
            console.print(table)

            return {
                "is_superadmin": user_profile.is_superadmin,
                "default_org_name": default_org.name,
                "default_org_uuid": default_org.organization_uuid,
            }
        except RequestHandlerException as err: 
            console.print("[red bold]Failed to authenticate to Contrast API")
            console.print(err)
            raise typer.Exit()


def autocomplete_orgs(searchterm: str):
    """Get a list of all orgs in the user's profile"""
    contrast = get_contrast_api()
    current_user_profile_orgs = contrast.profile.get_organizations_in_profile()
    
    for org in current_user_profile_orgs:
        if org.name.startswith(searchterm):
            yield (org.organization_uuid, org.name)


def get_contrast_auth() -> ContrastAPIConfig:
    """Get Contrast API config from file, if this exists."""
    try: 
        contrast_auth_config = ContrastAPIConfig.from_yaml_file(CONFIG_FILE)
        return contrast_auth_config
    except FileNotFoundError:
        console.log(f"Could not find config file. Please run [bold blue]`auth init`[/bold blue] to initialize the CLI.")
        raise typer.Exit()
    except TypeError: 
        console.log(f"Found a config file at '{CONFIG_FILE}', but could not load it. Is it malformed? Please run the [bold blue]auth init[/bold blue] command again!")
        raise typer.Exit()
    except Exception as err:
        console.log(f"Could not load config from file. Please run the [bold blue]auth init[/bold blue] command!")
        raise err
    

def get_contrast_api() -> ContrastAPI:
    """Get a ContrastAPI object from the ContrastAuth object"""
    try:
        contrast_auth_config = get_contrast_auth()
        return ContrastAPI.from_config(contrast_auth_config)
    except Exception as err:
        print(err)
        raise Exception("Could not load ContrastAuth object from file. Please run auth init to authenticate.")
    

@cli.command()
def set_profile(
        org_uuid: Annotated[str, typer.Argument(help="The Organization UUID to set as default", autocompletion=autocomplete_orgs)],
    ):
    """
    Choose a different organization from your profile to use as the default. 
    
    You must be a SuperAdmin to do this.
    """
    # First check that the auth file is ok before continuing
    contrast_auth = get_contrast_auth()

    if not contrast_auth.is_superadmin:
        raise typer.Exit("You must be a SuperAdmin to change your default org")
    
    console.print()
    console.print("[bold blue]Switching to a new Active Org in your Profile")

    contrast = get_contrast_api()

    new_api_key = contrast.base.get(f"superadmin/users/{org_uuid}/keys/apikey").data.get("api_key")
    org_name = contrast.base.get(f"superadmin/organizations/{org_uuid}").data.get('organization').get('name')

    contrast_auth.set_active_profile(org_uuid=org_uuid, api_key=new_api_key, org_name=org_name, config_file=CONFIG_FILE)

    new_contrast_api = get_contrast_api()
    organization = new_contrast_api.profile.get_profile_user_roles_for_org()

    console.print(f"\t - :white_check_mark: Active org set to '{organization.name}' ({organization.organization_uuid})")
    console.print(f"\t - {':white_check_mark: You have' if any(role in ['ROLE_ADMIN', 'ROLE_RULES_ADMIN'] for role in organization.roles) else ':x: You DO NOT'} ADMIN or RULES_ADMIN for the '{organization.name}' org ")

