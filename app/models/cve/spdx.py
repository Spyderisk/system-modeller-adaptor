#!/usr/bin/python3

from typing import Optional, List, Dict
from pydantic import BaseModel, Field

from collections import defaultdict


class GenericModel:
    def __init__(self, row):
        for column in row.index:
            setattr(self, column, row[column])

    def __repr__(self):
        return f"GenericModel({', '.join(f'{k}={v}' for k, v in self.__dict__.items())})"


class ConfFile(BaseModel):
    """ config file class that supports checksums """
    name: str
    checksum: str

class SPDXPackage(BaseModel):
    name: str = ""
    version: str = ""

class ExeFile(BaseModel):
    """ config file class that supports checksums """
    name: str
    owner: Optional[str] = None
    group: Optional[str] = None
    permissions: Optional[str] = None
    simlink: Optional[str] = None

    def parse_permissions(self):
        if len(self.permissions) != 10:
            raise ValueError("Invalid permission string length")

        permissions = {
            'is_directory': self.permissions[0] == 'd',
            'owner': {
                'read': self.permissions[1] == 'r',
                'write': self.permissions[2] == 'w',
                'execute': self.permissions[3] == 'x'
            },
            'group': {
                'read': self.permissions[4] == 'r',
                'write': self.permissions[5] == 'w',
                'execute': self.permissions[6] == 'x'
            },
            'others': {
                'read': self.permissions[7] == 'r',
                'write': self.permissions[8] == 'w',
                'execute': self.permissions[9] == 'x'
            }
        }
        return permissions

class Package(BaseModel):
    """ Package class for installed opkg packages """
    name: str
    version: str
    depends: Optional[List[str]] = []
    installed_time: str
    execfiles: Optional[Dict[str, ExeFile]] = Field(default_factory=lambda: defaultdict(ExeFile))
    conffiles: Optional[List[ConfFile]] = []
    db_found: bool = False
    db_desc: Optional[str] = ""
    db_categories: Optional[str] = ""
    db_releaseversion: Optional[str] = ""

    def __eq__(self, other):
        if isinstance(other, Package):
            return (self.name, self.version) == (other.name, other.version)
        return False

    def __hash__(self):
        return hash((self.name, self.version))

    def __str__(self):
        return f"Package(name={self.name}, version={self.version}, openWrt source: {self.db_found})"

