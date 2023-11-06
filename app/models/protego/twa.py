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


from pydantic import BaseModel
from ..dbmodel import DateTimeModelMixin, DBModelMixin
from ..rwmodel import RWModel

class TWAChange(BaseModel):
    cause: str
    asset_label: str
    twa_key: str
    changed_from: str
    changed_to: str

class TWA(BaseModel):
    cause: str
    model_id: str
    asset_id: str
    asset_label: str
    twa_key: str
    asserted_level_uri: str
    asserted_level_label: str
    changed_from: str
    changed_to: str

class TWAInDB(DBModelMixin, DateTimeModelMixin, RWModel, TWA):
    pass