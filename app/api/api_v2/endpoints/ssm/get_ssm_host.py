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

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import status
from fastapi.responses import JSONResponse

from app.crud.store import create_vjob
from app.crud.store import (acquire_session_lock, update_status)

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from ssmclientlib.exceptions import ApiException
from app.ssm.ssm_base import get_ssm_base

from app.ssm.protego.bg_check_model_exists import bg_check_model_exists

from fastapi.logger import logger

router = APIRouter(tags=['SSM Utils'])

@router.get("/ssm_host",
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def get_ssm_host( ssm: SSMClient = Depends(get_ssm_base),):
    """
    Get the Spyderisk service endpoint.

    :return: Spyderisk service URL
    """

    logger.info("Got get_ssm_host GET call")

    try:
        ssm_host = ssm.get_ssm_host()
    except ApiException as ex:
        raise HTTPException(status_code=ex.status, detail=f"{ex.reason}")

    if not ssm_host:
        raise HTTPException(status_code=404, detail="Model not found")

    return {"ssm_host": ssm_host}

