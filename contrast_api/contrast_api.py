import json
import logging
import requests
import yaml 

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from rich import print
from rich.logging import RichHandler
from uuid import UUID

from contrast_api.api_handlers import * 

logging.basicConfig(level="INFO", datefmt="[%X]", format="%(name)s: %(message)s", handlers=[RichHandler(markup=True)])
logger = logging.getLogger(__name__)


@dataclass
class ProfileAuth(yaml.YAMLObject):
    org_uuid: UUID
    api_key: str
    name: Optional[str] = None

    @classmethod
    def from_dict(cls):
        pass


@dataclass
class ContrastAPIConfig(yaml.YAMLObject):
    teamserver_url: str
    api_key: str
    auth_header: str
    is_superadmin: Optional[bool] = False
    default_profile: Optional[ProfileAuth] = None
    active_profile: Optional[ProfileAuth] = None

    @classmethod
    def from_yaml_file(cls, config_file: Path):
        """Load ContrastAuth object from a YAML file"""
        try: 
            logger.debug(f"Loading config file from {config_file}")
            contrast_config = yaml.safe_load(config_file.read_text())
            return cls(**contrast_config)
        except FileNotFoundError as err:
            logger.error(f"Could not find config file!: {err}")
            raise err
    
    def __post_init__(self):
        if self.default_profile:
            self.default_profile = ProfileAuth(**self.default_profile)
        if self.active_profile:
            self.active_profile = ProfileAuth(**self.active_profile)
        
    def to_yaml_file(self, config_file: Path):
        """Write ContrastAuth object to a YAML file"""
        logger.debug(f"Writing config file to '{config_file}'")
        with open(config_file, "w") as file:
            yaml.emitter.Emitter.process_tag = lambda self, *args, **kw: None
            yaml.dump(self.__dict__, file, sort_keys=False, allow_unicode=True, default_flow_style=False)
    
    def set_default_profile(self, org_uuid: str, api_key: str, config_file: Path, org_name: str = None):
        self.default_profile = ProfileAuth(name=org_name, org_uuid=org_uuid, api_key=api_key)
        self.to_yaml_file(config_file)

    def set_active_profile(self, org_uuid: str, api_key: str, config_file: Path, org_name: str = None):
        self.active_profile = ProfileAuth(name=org_name, org_uuid=org_uuid, api_key=api_key)
        self.to_yaml_file(config_file)
            

@dataclass
class ContrastAPIResponse:
    status_code: int
    message: str
    data: List[Dict]


class ContrastAPI:

    def __init__(self, session: requests.Session, api_config: ContrastAPIConfig):
        self.api_config = api_config
        self.session = session
        self.api_config = api_config

    @classmethod
    def from_config(cls, api_config: ContrastAPIConfig):
        session = requests.Session()
        session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "API-Key": api_config.active_profile.api_key if api_config.active_profile else api_config.api_key,
            "Authorization": api_config.auth_header
        })
        return cls(session, api_config)
    
    @property
    def base(self):
        return BaseAPI(self.session, self.api_config)
    
    @property
    def policy(self):
        return PolicyHandler(self.session, self.api_config)

    @property
    def profile(self):
        return ProfileHandler(self.session, self.api_config)
