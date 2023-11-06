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


from fastapi import (APIRouter, Depends, Path, HTTPException, status)
from bson.objectid import ObjectId

from app.crud.store import get_vjob

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.vjob import VJobInDB

from fastapi.logger import logger

router = APIRouter(tags=['Cyberkit4SME'])

@router.get("/models/{model_webkey}/jobs/{job_id}",
            response_model=VJobInDB,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def check_job_status(job_id: str = Path(..., title="Task calculation update job id"),
                     model_webkey: str = Path(..., title="Model webkey"),
                     db_client: AsyncIOMotorClient = Depends(get_database)):
    """
    This is an auxilary call to support asynchronous mode calls. It allows to
    check the status of a background task/job (e.g. risk calculation).

    :param str model_webkey: the webkey of the SSM model corresponding to the live system

    :param str job_id: the ID of the background task.

    :return: status of the requested background task.
    """
    logger.info(f"check background job {job_id} status")

    if not ObjectId.is_valid(job_id):
        logger.debug(f"InvalidId for {job_id}")
        raise HTTPException(status_code=404, detail="Invalid task ID")

    job_status = await get_vjob(db_client, ObjectId(job_id))

    if not job_status:
        logger.warn(f"invalid job id? {job_id}")
        raise HTTPException(status_code=404, detail="No background task found")

    logger.info(f"job status {job_status, type(job_status)}")
    
    return job_status

