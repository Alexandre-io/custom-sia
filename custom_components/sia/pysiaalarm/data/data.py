"""Data related utils for pysiaalarm."""
from __future__ import annotations

import json
from dataclasses import dataclass

import pkg_resources
import asyncio

FILE_SIA_CODES = "sia_codes.json"
FILE_XDATA = "xdata.json"
FILE_ADM_MAPPING = "adm_mapping.json"


@dataclass
class SIACode:
    """Class for SIACodes."""

    code: str
    type: str
    description: str
    concerns: str


@dataclass
class SIAXData:
    """Class for Xdata."""

    identifier: str
    name: str
    description: str
    length: int
    characters: str
    value: str | None = None


def _load_data(file: str) -> dict:
    """Load the one of the data json files."""
    stream = pkg_resources.resource_stream(__name__, file)
    return json.load(stream)

async def _load_file(file:str) -> dict:
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _load_data, file)
    return result

def _load_sia_codes() -> dict[str, SIACode]:
    """Alias for loading sia codes file."""
    task = asyncio.create_task(_load_file(FILE_SIA_CODES))
    asyncio.get_running_loop().run_until_complete(task)
    data = task.result()
    return {key: SIACode(**value) for (key, value) in data.items()}

def _load_xdata() -> dict[str, SIAXData]:
    """Alias for loading xdata file."""
    data = _load_data(FILE_XDATA)
    return {key: SIAXData(**value) for (key, value) in data.items()}


def _load_adm_mapping() -> dict[str, dict[str, str]]:
    """Alias for loading adm mapping file."""
    return _load_data(FILE_ADM_MAPPING)
