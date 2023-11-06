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


from typing import Optional

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import Response
from fastapi.responses import PlainTextResponse
from fastapi import status
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

#from app.models.user import User
#from app.api.auth import get_current_user

from app.crud.store import (create_vjob, get_vjob, get_state, get_recommendations)
from app.crud.store import (acquire_session_lock, update_status)
from app.crud.store import release_session_lock

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.risk import State

from app.ssm.common_v2.bg_risk_calc import bg_calculate_model_risk
from app.ssm.common_v2.bg_risk_calc import bg_calculate_model_risk_simple

from app.core.config import RISK_CALC_MODE

from fastapi.logger import logger


router = APIRouter(tags=['SSM Utils'])

@router.post("/models/{model_webkey}/calc-risk-block",
             #response_model=State,
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 },
             status_code=status.HTTP_202_ACCEPTED)
async def calculate_risk_blocking(model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm: SSMClient = Depends(get_ssm_base),
                      risk_mode: str = RISK_CALC_MODE,
                      ):
    """

    Calculate model risk operation, it takes as a path parameter the model ID.
    This is a blocking call that instantiates the current model risk
    calculations.

    :param str model_id: Model ID that can be used to access the model

    :return status: Returns the background job ID of the requested risk
                    calculation task

    """
    logger.info("Got calc_risk call blocking mode")

    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create calc-risk blocking job")

    vjob_id = str(vjob.id)
    logger.info(f"calc risk blocking job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.info(f"starting foreground job")

    try:
        model_state = bg_calculate_model_risk(model_webkey, ssm, risk_mode)
    except Exception as e:
        logger.error("Exception in calculate risk endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"Calculate risk failed for {model_webkey}")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_client, vjob_id)

    return model_state


#@router.post("/models/{model_webkey}/calc-risk",
#             #response_model=State,
#             responses={
#                 404: {"description": "Item not found"},
#                 423: {"description": "Resource locked, by another process try again later."},
#                 },
#             status_code=status.HTTP_202_ACCEPTED)
#async def calculate_risk_blocking_simple(model_webkey: str = Path(..., title="Model webkey"),
#                      db_client: AsyncIOMotorClient = Depends(get_database),
#                      ssm: SSMClient = Depends(get_ssm_base),
#                      risk_mode: str = RISK_CALC_MODE,
#                      ):
#    """
#
#    Calculate model risk operation, it takes as a path parameter the model ID.
#    This is a blocking call that instantiates the current model risk
#    calculations.
#
#    :param str model_id: Model ID that can be used to access the model
#
#    :return status: Returns the background job ID of the requested risk
#                    calculation task
#
#    """
#    logger.info("Got calc_risk call blocking mode")
#
#    vjob = await create_vjob(db_client, {"modelId": model_webkey})
#    if not vjob:
#        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
#                            detail="Failed to create calc-risk blocking job")
#
#    vjob_id = str(vjob.id)
#    logger.info(f"calc risk blocking job {vjob}, {vjob_id}")
#
#    # acquire session lock
#    lock_acquired = await acquire_session_lock(db_client, vjob_id)
#
#    if not lock_acquired:
#        # update status of job as REJECTED
#        await update_status(db_client, vjob_id, "REJECTED")
#        logger.debug("Failed to acquire session lock return 423")
#        raise HTTPException(status_code=status.HTTP_423_LOCKED,
#                            detail="Resource is locked by another process, try again later.")
#
#    logger.info(f"starting foreground job")
#
#    try:
#        model_state = bg_calculate_model_risk_simple(model_webkey, ssm, risk_mode)
#    except Exception as e:
#        logger.error("Exception in calculate risk endpoint: %s\n" % e)
#        raise HTTPException(status_code=404, detail=f"Calculate risk failed for {model_webkey}")
#    finally:
#        logger.info("releasing session lock")
#        await release_session_lock(db_client, vjob_id)
#
#    return model_state

