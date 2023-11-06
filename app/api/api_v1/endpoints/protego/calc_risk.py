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
from fastapi import status
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

#from app.models.user import User
#from app.api.auth import get_current_user

from app.crud.store import (create_vjob, get_vjob, get_state, get_recommendations)
from app.crud.store import (acquire_session_lock, update_status)

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.vjob import VJobStatus
from app.models.risk import State
from app.models.protego.recommendations import ObjectRecommendation

from app.ssm.protego.bg_mitigation import bg_mitigation

from fastapi.logger import logger


router = APIRouter(tags=['SIEM'])

@router.post("/models/{modelId}/calc-risks",
             response_model=VJobStatus,
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 },
             status_code=status.HTTP_202_ACCEPTED)
async def calculate_risks(bg_tasks: BackgroundTasks,
                          modelId: str = Path(..., title="ModelId webkey"),
                          #user: User = Depends(get_current_user),
                          db_client: AsyncIOMotorClient = Depends(get_database),
                          ssm: SSMClient = Depends(get_ssm_base),
                          ):
    """

    Calculate model risk operation, it takes as a path parameter the model ID.
    This is an asynchronous call that instantiates the current model risk
    calculation and finds risk mitigation recommendations.

    Both risk description and mitigation recommendations are asynchronously
    pushed in to a Kafka queue.

    :param str model_id: Model ID that can be used to access the model

    :return status: Returns the background job ID of the requested risk
                    calculation task

    """
    logger.info("Got calc_risk call")

    vjob = await create_vjob(db_client, {"modelId": modelId})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create calc-risk job")

    vjob_id = str(vjob.id)
    logger.info(f"calc risk job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.info(f"starting bg job")
    bg_tasks.add_task(bg_mitigation, modelId, vjob_id, db_client, ssm)

    logger.info(f"asynchronous return {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}


@router.get("/models/download/risk/{vid}",
            response_model=State,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def download_risk(vid: str = Path(..., title="Download risk calculation"),
                        db_client: AsyncIOMotorClient = Depends(get_database)):
    """
    Get risk calculation

    :param vid: The ID of risk-calc task

    :return: risk document
    """

    logger.info("download risk calculation")
    job_status = await get_vjob(db_client, ObjectId(vid))

    if not job_status:
        logger.warn(f"invalid job id? {vid}")
        raise HTTPException(status_code=404, detail="No risk calculation found")

    if not job_status.status == "FINISHED":
        logger.debug(f"background task not finished? {job_status.status}")
        raise HTTPException(status_code=404, detail="No risk calculation found")

    risk_response = await get_state(db_client, vid)

    if not risk_response:
        logger.debug(f"risk item not found in db {vid}")
        raise HTTPException(status_code=404, detail="No risk calculation found")

    return risk_response


@router.get("/models/download/recommendations/{vid}",
            response_model=ObjectRecommendation,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def download_recommendations(vid: str = Path(..., title="Download risk mitigation recommendations"),
                                   db_client: AsyncIOMotorClient = Depends(get_database)):
    """
    Get risk mitigation recommendations

    :param vid: The ID of risk-calc task

    :return: risk mitigation recommendation document
    """

    logger.info("download recommendations")
    job_status = await get_vjob(db_client, ObjectId(vid))

    if not job_status:
        logger.warn(f"invalid job id? {vid}")
        raise HTTPException(status_code=404, detail="No recommendations found")

    if not job_status.status == "FINISHED":
        logger.debug(f"background task not finished? {job_status.status}")
        raise HTTPException(status_code=404, detail="No recommendations found")

    recommendations = await get_recommendations(db_client, vid)

    if not recommendations:
        logger.debug(f"recommendation item not found in db {vid}")
        raise HTTPException(status_code=404, detail="No recommendations found")

    return recommendations
