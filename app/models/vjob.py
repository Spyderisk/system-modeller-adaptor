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


from typing import Optional  # , List, Dict
#from datetime import datetime
from pydantic import BaseModel

from .dbmodel import DateTimeModelMixin, DBModelMixin
from .rwmodel import RWModel

class VJobStatus(BaseModel):
    jobid: str
    status: str


class VJobBase(RWModel):
    modelId: str
    status: str = 'CREATED'
    err_msg: Optional[str]
    #jobStatus: Optional[VulneraJobStatus] = None
    #__id__: Optional[str] = None


class VJob(DateTimeModelMixin, VJobBase):
    messages: Optional[str] = None


class VJobInDB(DBModelMixin, VJob):
    pass


class VJobInResponse(RWModel):
    vjob: VJob

