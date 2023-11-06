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


from fastapi import (APIRouter, Depends, Path, HTTPException, status)
from bson.objectid import ObjectId

from app.crud.store import get_vjob

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.vjob import VJobInDB

from fastapi.logger import logger

router = APIRouter(tags=['monitor'])

@router.get("/models/describe/task-status/{vid}",
            response_model=VJobInDB,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def check_task(vid: str = Path(..., title="Task calculation update job id"),
                     db_client: AsyncIOMotorClient = Depends(get_database)):
    """
    This is an auxilary call to support asynchronous mode calls. It allows to
    check the status of the background task.

    :param str vid: The ID of the task.

    :return: Status of a background task.
    """
    logger.info(f"describe vJob {vid} status")

    if not ObjectId.is_valid(vid):
        logger.debug(f"InvalidId for {vid}")
        raise HTTPException(status_code=404, detail="Invalid task ID")

    job_status = await get_vjob(db_client, ObjectId(vid))

    if not job_status:
        logger.warn(f"invalid job id? {vid}")
        raise HTTPException(status_code=404, detail="No background task found")

    logger.info(f"job status {job_status, type(job_status)}")
    return job_status


@router.get("/check-ssm",
            responses={
                404: {"description": "SSM not found"},
                },
            status_code=status.HTTP_200_OK)
async def check_ssm(ssm: SSMClient = Depends(get_ssm_base)):
    """
    This is an auxilary call to check ssm connection

    :return: Status of a ssm connection.
    """
    if not ssm.check_ssm():
        raise HTTPException(status_code=404, detail="SSM connection test failed")
    else:
        return "SSM connection test passed"
