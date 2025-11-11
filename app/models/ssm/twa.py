##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2021
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre of Gamma House, Enterprise Road,
## Chilworth Science Park, Southampton, SO16 7NS, UK.
##
## This software may not be used, sold, licensed, transferred, copied
## or reproduced in whole or in part in any manner or form or in or
## on any media by any person other than in accordance with the terms
## of the Licence Agreement supplied with the software, or otherwise
## without the prior written consent of the copyright owners.
##
## This software is distributed WITHOUT ANY WARRANTY, without even the
## implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
## PURPOSE, except where stated in the Licence Agreement supplied with
## the software.
##
##      Created By :            Panos Melas
##      Created Date :          2021-04-29
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

import textwrap
from pydantic import BaseModel, Field
from typing import Optional, Tuple
from ..dbmodel import DateTimeModelMixin, DBModelMixin
from ..rwmodel import RWModel

class TWASChangeRecord(BaseModel):
    cvss_vector: Optional[str] = None
    twas: Optional[dict[str, Optional[str]]] = None

    def __str__(self) -> str:
        twas_str = "\n     ".join(f"      - {key} -> {value}" for key, value in (self.twas or {}).items() if value)
        return (
            f"CVSS Vector: {self.cvss_vector or 'N/A'}\n"
            f"         Suggested Modification:\n"
            f"     {twas_str if twas_str else '  N/A'}\n"
        )


class CVE2TWAReport(BaseModel):
    asset_name: Optional[str] = None
    asset_id: Optional[str] = None
    cve_name: Optional[str] = None
    description: Optional[str] = None
    cve_score: Optional[Tuple[str, float, str]] = None
    cvss_list: Optional[list[str]] = None
    cwe_list: Optional[list[str]] = None
    proposed_twas: Optional[list[TWASChangeRecord]] = []

    def __str__(self) -> str:
        cvss_str = "\n    - ".join(self.cvss_list) if self.cvss_list else "N/A"
        cwe_str = ", ".join(self.cwe_list) if self.cwe_list else "N/A"
        twas_str = "\n    - " + "\n     - ".join(str(item) for item in self.proposed_twas) if self.proposed_twas else "N/A"
        desc_str =  textwrap.fill(self.description, width=80, initial_indent="\t", subsequent_indent="\t")
        return (
            "=============CVE2TWAReport==============\n\n"
            f"{self.cve_name or 'N/A'} summary\n\n"
            f"  Severity CVSS score: {self.cve_score if self.cve_score else 'N/A'}\n\n"
            f"  Description:\n{desc_str}\n\n"
            f"  CVSS Vectors:\n    - {cvss_str}\n\n"
            f"  CWEs: {cwe_str}\n\n"
            f"  Target asset: {self.asset_name} (id: {self.asset_id})\n\n"
            f"  Proposed TWA Adjustments:\n{twas_str}\n\n"
        )


class TWASChanges(BaseModel):
    cve_name: Optional[str] = None
    cvss_vector: Optional[str] = None
    twas: Optional[dict[str, Optional[str]]] = None

    def __str__(self) -> str:
        twas_str = "\n  ".join(f"  - {key} --> {value}" for key, value in (self.twas or {}).items() if value)
        return f"""TWA suggested changes for {self.cve_name}
  CVSS vector: {self.cvss_vector}
  changes:
  {twas_str if twas_str else 'N/A'}"""


class TWAChange(BaseModel):
    cause: str
    asset_label: str
    twa_key: str
    changed_from: str
    changed_to: str


class TWA(BaseModel):
    cause: str
    m_webkey: str = Field(alias="model_id")
    asset_id: str
    asset_label: str
    twa_key: str
    asserted_level_uri: str
    asserted_level_label: str
    changed_from: str
    changed_to: str

class TWAInDB(DBModelMixin, DateTimeModelMixin, RWModel, TWA):
    pass
