# Import commonly used rich stuff for amazing cli output
from rich import print
from rich.console import Console
from rich.traceback import install


import typer
import typer.rich_utils

# Set the max width for the console output. 
# MAX_CONSOLE_WIDTH = 200
# By default, Typer will resize the width of the console to use the full witdth of the terminal window, 
# but this sometimes makes the help text difficult to read.
typer.rich_utils._TERMINAL_WIDTH = typer.get_terminal_size().columns
typer.rich_utils.STYLE_HELPTEXT = "bold white"

# Configure a Rich instance
console = Console(markup=True, width=int(typer.rich_utils._TERMINAL_WIDTH))
install(console=console, theme="monokai", width=typer.rich_utils._TERMINAL_WIDTH, locals_max_string=typer.rich_utils._TERMINAL_WIDTH, locals_max_length=typer.rich_utils._TERMINAL_WIDTH)

# raise Exception("This is a test")
# Implement monkey-patch for Typer's parsing of markdown docstrings
# https://github.com/tiangolo/typer/issues/447
from integrations_cli._docstring_help_text_fix import _get_custom_help_text, _make_command_help
typer.rich_utils._get_help_text = _get_custom_help_text
typer.rich_utils._make_command_help = _make_command_help

from pathlib import Path
CONFIG_DIR = Path(typer.get_app_dir(__name__))
CONFIG_FILE = CONFIG_DIR / "config.yaml"
