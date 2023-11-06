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


from typing import Optional, List
from pydantic import BaseModel
from app.models.risk import RiskVector, Risk
from app.models.risk import Asset, State

from .dbmodel import DateTimeModelMixin, DBModelMixin
from .rwmodel import RWModel
from .snake2camel import to_camel

class SVGPlot(BaseModel):
    model_id: str
    svg: str
    jobid: Optional[str]
    recid: Optional[str]

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True

class StoredSVGPlotInDB(DBModelMixin, DateTimeModelMixin, RWModel, SVGPlot):
    pass

