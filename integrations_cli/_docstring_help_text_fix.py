"""Fix rendering help text from  Markdown docstrings in Typer

Monkey-patch the `typer.rich_utils._get_help_text` function to properly render Markdown 
docstrings as described in https://github.com/tiangolo/typer/issues/447.  

The monkey-patch fixes Typer's parsing of the Docstring, so that new lines are parsed. 
This is a temporary fix until the Typer team implement this upstream.
"""

import inspect
import re
from typing import Union, Iterable

import click
from rich.console import group
from rich.markdown import Markdown
from rich.text import Text
from typer.core import MarkupMode
from typer.rich_utils import (
    MARKUP_MODE_MARKDOWN, 
    MARKUP_MODE_RICH,
    STYLE_HELPTEXT, 
    STYLE_HELPTEXT_FIRST_LINE, 
    STYLE_OPTION_HELP,
    _make_rich_rext
)


@group()
def _get_custom_help_text(
    *,
    obj: Union[click.Command, click.Group],
    markup_mode: MarkupMode,
) -> Iterable[Union[Markdown, Text]]:
    # Fetch and dedent the help text
    help_text = inspect.cleandoc(obj.help or "")

    # Trim off anything that comes after \f on its own line
    help_text = help_text.partition("\f")[0]

    # Get the first paragraph
    first_line = help_text.split("\n\n")[0]
    # Remove single linebreaks
    if markup_mode != MARKUP_MODE_MARKDOWN and not first_line.startswith("\b"):
        first_line = first_line.replace("\n", " ")
    yield _make_rich_rext(
        text=first_line.strip(),
        style=STYLE_HELPTEXT_FIRST_LINE,
        markup_mode=markup_mode,
    )

    # Get remaining lines, remove single line breaks and format as dim
    remaining_paragraphs = help_text.split("\n\n")[1:]
    if remaining_paragraphs:
        remaining_lines = inspect.cleandoc("\n\n".join(remaining_paragraphs).replace("<br/>", "\\"))
        yield _make_rich_rext(
            text=remaining_lines,
            style="",
            markup_mode=markup_mode,
        )


def _make_command_help(
    *,
    help_text: str,
    markup_mode: MarkupMode,
) -> Union[Text, Markdown]:
    paragraphs = inspect.cleandoc(help_text).split("\n\n")
    first_line = paragraphs[0]
    # Remove single linebreaks
    if markup_mode != MARKUP_MODE_RICH and not first_line.startswith("\b"):
        first_line = first_line.replace("\n", " ")
    elif first_line.startswith("\b"):
        first_line = first_line.replace("\b\n", "")
    
    # Remove markdown heading hashes from short help text as this breaks the 
    # rendering of the help text: 
    first_line = re.sub(r"^#+\s", "", first_line)

    return _make_rich_rext(
        text=first_line.strip(),
        style=STYLE_OPTION_HELP,
        markup_mode=markup_mode,
    )
