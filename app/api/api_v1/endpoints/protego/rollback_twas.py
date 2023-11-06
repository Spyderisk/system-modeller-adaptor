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

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.crud.store import (acquire_session_lock, update_status)

from app.ssm.protego.bg_rollback_twas import  bg_rollback_twas, bg_list_twas
from fastapi.logger import logger


router = APIRouter(tags=['SIEM'])


@router.post("/models/{modelId}/reset-vulnerabilities",
            responses={
                404: {"description": "Item not found"},
                423: {"description": "Resource locked, by another process try again later."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def reset_vulnerability_changes(modelId: str = Path(..., title="ModelId webkey"),
                                         db_client: AsyncIOMotorClient = Depends(get_database),
                                         ssm: SSMClient = Depends(get_ssm_base),
                                         ):
    """
    Reset model TWAs that were changed by previous vulnerabilities calls.

    This method should be used to mark the start of a new session followed by
    vulnerability updates and risk caclulation/recommendation calls.

    The call is BLOCKING.

    :param str model_id: Model ID that can be used to access the model

    :param identification params

    :return: None
    """

    logger.info(f"Reset TWAs for model {modelId}")

    vjob = await create_vjob(db_client, {"modelId": modelId})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to reset TWAs job")

    vjob_id = str(vjob.id)
    logger.info(f"Reset model TWAs job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.debug(f"starting reset model TWAs blocking task: {vjob_id}")
    await bg_rollback_twas(modelId, vjob_id, db_client, ssm)
    logger.debug(f"finished resetting model TWA blocking task: {vjob_id}")

    logger.debug(f"release session lock for reset TWAs task: {vjob_id}")

    return JSONResponse(status_code=status.HTTP_202_ACCEPTED)


