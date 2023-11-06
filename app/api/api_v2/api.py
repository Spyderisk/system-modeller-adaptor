##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2022
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Electronics and Computer Sciences, Faculty of
## Engineering and Physical Sciences, Highfield Campus, SO17 1BJ, UK.
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
##      Created Date :          2022-03-23
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////


import os
from fastapi import APIRouter

from .endpoints.cyberkit4sme import status
from .endpoints.cyberkit4sme import openvas_report
from .endpoints.cyberkit4sme import recommendations
from .endpoints.cyberkit4sme import result
from .endpoints.cyberkit4sme import graphs
from .endpoints.cyberkit4sme import state_reports
from .endpoints.cyberkit4sme import calculate_risk

from .endpoints.ssm import unlock
from .endpoints.ssm import rollback_twas
from .endpoints.ssm import check_model
#from .endpoints.ssm import calc_risk
from .endpoints.ssm import validate

from app.api.api_v1.endpoints.fogprotect import fog_protect
from app.api.api_v1.endpoints.fogprotect import mock_adaptation_service

from app.core.config import SSM_ADAPTOR_MODE

router = APIRouter(prefix="/v2")

# generic API
router.include_router(status.router)
router.include_router(unlock.router)
router.include_router(check_model.router)
#router.include_router(calc_risk.router)
router.include_router(validate.router)

# Cyberkit4SME mode
if SSM_ADAPTOR_MODE.lower() in ["cyberkit4sme", "debug", "all"]:
    router.include_router(openvas_report.router)
    router.include_router(recommendations.router)
    router.include_router(result.router)
    router.include_router(graphs.router)
    router.include_router(rollback_twas.router)
    router.include_router(state_reports.router)
    router.include_router(calculate_risk.router)

# FogProtect mode
if SSM_ADAPTOR_MODE.lower() in ["fogprotect", "debug", "all"]:
    router.include_router(fog_protect.router)
    router.include_router(mock_adaptation_service.router)

