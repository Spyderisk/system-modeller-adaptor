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


import os
from fastapi import APIRouter

from .endpoints import  login
from .endpoints.protego import (vulnerability, calc_risk, assets, zap_vul, rollback_twas)
from .endpoints.fogprotect import fog_protect
from .endpoints.fogprotect import mock_adaptation_service
from .endpoints.monitor import check_status
from .endpoints.debug import list_twas
from .endpoints.ssm import get_risk_vector, unlock, validate, check_model

#router = APIRouter(prefix="/v1")
router = APIRouter()

router.include_router(login.router)
router.include_router(check_status.router)
router.include_router(get_risk_vector.router)
router.include_router(unlock.router)
router.include_router(rollback_twas.router)
router.include_router(validate.router)
router.include_router(check_model.router)

ssm_adaptor_mode = os.getenv("SSM_ADAPTOR_MODE", "ALL")

if ssm_adaptor_mode.lower() in ["fogprotect", "debug", "all"]:
    router.include_router(fog_protect.router)
    router.include_router(mock_adaptation_service.router)

if ssm_adaptor_mode.lower() in ["protego", "debug", "all"]:
    router.include_router(vulnerability.router)
    router.include_router(calc_risk.router)
    router.include_router(assets.router)
    router.include_router(zap_vul.router)

if ssm_adaptor_mode.lower() in ["debug", "all"]:
    router.include_router(list_twas.router)

