##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2025
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Highfield Campus, SO17 1BJ, UK.
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
##      Created Date :          2025-11-10
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////


import random
from typing import Optional, List, Union
from typing import Literal, ForwardRef
from pydantic import BaseModel, Field, validator, model_validator
from enum import Enum

from ..dbmodel import DateTimeModelMixin, DBModelMixin
from ..rwmodel import RWModel
from ..snake2camel import to_camel

from datetime import datetime, timedelta
from dateutil import parser

from fastapi.logger import logger

import tempfile
import shutil
from pathlib import Path

class ReportingMessage(BaseModel):
    """ Reporting tool job object """
    returncode: Optional[str] = ""
    stdout: Optional[str] = ""
    stderr: Optional[str] = ""
    tempdir: str = Field(default_factory=lambda: tempfile.mkdtemp(prefix="reporting_"))
    nq_filename: Optional[str] = ""
    output_filename: Optional[Path] = None
    status: str = "created"
    jtype: Literal["SYNC", "ASYNC"] = "SYNC"
    iso: Literal['27001', '14971'] = "" # ISO standard for output format
    report_type: Literal["security", "compliance", "combined"] = "security"
    output_format: Literal["csv", "pdf"] = "csv"

    def model_post_init(self, __context):
        # set output_filename dynamically after init
        if not self.output_filename:
            self.output_filename = Path(self.tempdir) / f"report.{self.output_format}"

    def cleanup(self):
        """Remove the temporary directory and its contents."""
        shutil.rmtree(self.tempdir, ignore_errors=True)

class ReportingMessageInDB(DBModelMixin, DateTimeModelMixin, RWModel, ReportingMessage):
    ssm_model_id: Optional[str] = None


class ReportingInfo(DBModelMixin, DateTimeModelMixin, RWModel):
    ssm_model_id: Optional[str] = None

