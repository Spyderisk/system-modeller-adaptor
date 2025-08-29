#!/usr/bin/python3

from typing import Optional, List, Dict
from pydantic import BaseModel, Field
from collections import defaultdict

class ProductCVE(BaseModel):
    """ object to associate product with CVE """
    product: str
    cve_number: str


class CVESBOM(BaseModel):
    """ CVE from SBOM object """
    vendor: str
    product: str
    version: str
    cve_number: str
    severity: str
    score: str
    source: str
    cvss_version: str
    cvss_vector: str
    paths: Optional[str] = ""
    remarks: str
    comments: Optional[str] = ""

    def parse_cvss_vector(self):
        if self.cvss_vector == "unknown":
            return None
        cvss_dict = {}
        for vector in  self.cvss_vector.split('/'):
            key, value = vector.split(':')
            cvss_dict[key] = value
        return cvss_dict


    def parse_cvss_vector1(self):
        ver_parts = self.cvss_version.split('.')
        if len(ver_parts) >=2 and ver_parts[0] == '3':
            print("version 3", self.cvss_version)
        else:
            print("not version 3,", self.cvss_version)

