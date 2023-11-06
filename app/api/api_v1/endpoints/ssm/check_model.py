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
from ssm_api_client.exceptions import ApiException
from app.ssm.ssm_base import get_ssm_base

from app.ssm.protego.bg_check_model_exists import bg_check_model_exists

from fastapi.logger import logger

router = APIRouter(tags=['SSM'])

@router.get("/models/{modelId}/check-model-exists",
            response_model=bool,
            responses={
                404: {"description": "Item not found"},
                423: {"description": "Resource locked, by another process try again later."},
                },
            status_code=status.HTTP_200_OK)
async def check_model_exists(modelId: str = Path(..., title="ModelId webkey"),
                         db: AsyncIOMotorClient = Depends(get_database),
                         ssm: SSMClient = Depends(get_ssm_base),
                         ):
    """
    Check provided model exists. This a blocking call.

    :param str model_id: Model ID that can be used to access the model

    :return:  validation response
    """

    logger.info("Got check model  GET call")

    vjob = await create_vjob(db, {"modelId": modelId})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create calc-risk job")

    vjob_id = str(vjob.id)
    logger.info(f"check model job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.info(f"starting fg job")
    try:
        val_response = await bg_check_model_exists(modelId, vjob_id, db, ssm)
    except ApiException as ex:
        raise HTTPException(status_code=ex.status, detail=f"{ex.reason}")


    return val_response
