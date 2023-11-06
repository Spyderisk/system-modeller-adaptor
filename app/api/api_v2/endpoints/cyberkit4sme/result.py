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
from fastapi import Response
from fastapi import status
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

#from app.models.user import User
#from app.api.auth import get_current_user

from app.crud.store import (create_vjob, get_vjob, get_recommendations)
from app.crud.store import (get_plot)
from app.crud.store import (acquire_session_lock, update_status)

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.protego.recommendations import ObjectRecommendation
from app.models.graph import SVGPlot

from app.ssm.protego.bg_mitigation import bg_mitigation

from fastapi.logger import logger


router = APIRouter(tags=['Cyberkit4SME'])

@router.get("/models/{model_webkey}/recommendations/{job_id}/result",
            response_model=ObjectRecommendation,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def download_recommendations(job_id: str = Path(..., title="Download risk mitigation recommendations"),
                                   model_webkey: str = Path(..., title="Model webkey"),
                                   db_client: AsyncIOMotorClient = Depends(get_database)):
    """
    Get risk calculation and mitigation recommendations

    :param job_id: The ID of risk-calc and recommendations task

    :return: risk mitigation recommendations document
    """

    logger.info("download recommendations")
    job_status = await get_vjob(db_client, ObjectId(job_id))

    if not job_status:
        logger.warn(f"invalid job id? {job_id}")
        raise HTTPException(status_code=404, detail="No recommendations found")

    if not job_status.status == "FINISHED":
        logger.debug(f"background task not finished? {job_status.status}")
        raise HTTPException(status_code=404, detail="No recommendations found")

    recommendations = await get_recommendations(db_client, job_id)

    if not recommendations:
        logger.debug(f"recommendation item not found in db {job_id}")
        raise HTTPException(status_code=404, detail="No recommendations found")

    return recommendations


@router.get("/models/{model_webkey}/recommendations/{job_id}/{rec_id}/plot",
            #response_model=SVGPlot,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def download_plot(rec_id:str = Path(..., title="Recommendation id"),
                                   job_id: str = Path(..., title="Download risk mitigation recommendations"),
                                   model_webkey: str = Path(..., title="Model webkey"),
                                   db_client: AsyncIOMotorClient = Depends(get_database)):
    """
    Get recommendation plot

    :param job_id: The ID of risk-calc and recommendations task
    :param rec_id: The ID of the recommendation plot

    :return: SVG plot document
    """

    logger.info(f"download recommendation plot {rec_id}")
    job_status = await get_vjob(db_client, ObjectId(job_id))

    if not job_status:
        logger.warn(f"invalid job id? {job_id}")
        raise HTTPException(status_code=404, detail="No recommendation plot found")

    if not job_status.status == "FINISHED":
        logger.debug(f"background task not finished? {job_status.status}")
        raise HTTPException(status_code=404, detail="No recommendation plot found")

    svg_plot = await get_plot(db_client, job_id, rec_id)

    if not svg_plot:
        logger.debug(f"recommendation plot {rec_id} not found in db {job_id}")
        raise HTTPException(status_code=404, detail=f"No plot found for recommendation {rec_id}")

    #return svg_plot
    return Response(content=svg_plot.svg, media_type="application/xml")

