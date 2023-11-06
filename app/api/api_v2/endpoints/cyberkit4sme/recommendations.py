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


from typing import Optional

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import status
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

from app.crud.store import (create_vjob, get_vjob, get_recommendations)
from app.crud.store import (acquire_session_lock, update_status)

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.vjob import VJobStatus

from app.ssm.cyberkit4sme.bg_shortest_path import bg_shortest_path_recommendation_combined

from fastapi.logger import logger


router = APIRouter(tags=['Cyberkit4SME'])

@router.post("/models/{model_webkey}/recommendations",
             response_model=VJobStatus,
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 },
             status_code=status.HTTP_202_ACCEPTED)
async def calculate_recommendations(bg_tasks: BackgroundTasks,
                          model_webkey: str = Path(..., title="ModelId webkey"),
                          db_client: AsyncIOMotorClient = Depends(get_database),
                          ssm: SSMClient = Depends(get_ssm_base),
                          risk_mode: str = 'CURRENT',
                          ):
    """

    This call calculates risk mitigation recommendations for a given SSM model
    identified by modelId.

    The recommendations algorithm will first create a 'copy' of the initial
    system model and apply valid state reports before performing any
    recommendations calculations. At the end of the calculation, any changes
    made to the model will be reverted.

    This call is asynchronous; the return response is simply the job Id of the
    background risks/recommendations calculation, along with the initial status
    of the job.

    The job status can be further queried via a call to the 'check job status'
    endpoint.

    :param str model_webkey: the webkey of the SSM model corresponding to the
    live system

    :param str risk_mode: specify the SSM risk model calculation, i.e.
    CURRENT|FUTURE, default is CURRENT

    :return status: Returns the job ID of the background task and current status

    """

    logger.info(f"Got calculate_recommendations call with risk mode: {risk_mode}")

    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create calc-risk job")

    vjob_id = str(vjob.id)
    logger.info(f"recommendations job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.info(f"starting bg job")
    bg_tasks.add_task(bg_shortest_path_recommendation_combined, model_webkey, vjob_id,
            db_client, ssm, risk_mode)

    logger.info(f"asynchronous return {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}

