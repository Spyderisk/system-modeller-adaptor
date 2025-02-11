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

from .endpoints.state_report_management import status
from .endpoints.state_report_management import openvas_report
from .endpoints.state_report_management import recommendations
from .endpoints.state_report_management import result
from .endpoints.state_report_management import graphs
from .endpoints.state_report_management import state_reports
from .endpoints.state_report_management import calculate_risk

from .endpoints.indicators import aira_report

from .endpoints.ssm import unlock
from .endpoints.ssm import rollback_twas
from .endpoints.ssm import check_model
#from .endpoints.ssm import calc_risk
from .endpoints.ssm import validate
from .endpoints.ssm import get_ssm_host

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
router.include_router(get_ssm_host.router)

router.include_router(aira_report.router)

# State Report Management mode
if SSM_ADAPTOR_MODE.lower() in ["state_report_management", "debug", "all"]:
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

