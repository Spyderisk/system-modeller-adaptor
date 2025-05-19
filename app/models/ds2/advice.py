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
##      Created By :            Ken Meacham
##      Created Date :          2025-05-02
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

from typing import List, Literal
from pydantic import BaseModel

class DataType(BaseModel):
    classification: str
    categories: List[str]

class AdviceInput(BaseModel):
    deployment_type: Literal['cloud', 'local']
    data_type: DataType
    known_migrations: List[str]
    user_priorities: List[str]