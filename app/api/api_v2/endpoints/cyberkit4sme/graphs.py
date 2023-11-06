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
from fastapi.responses import PlainTextResponse
from fastapi import status
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

from app.crud.store import (create_vjob, get_vjob, get_recommendations)
from app.crud.store import (get_plot)
from app.crud.store import (acquire_session_lock, update_status)
from app.crud.store import release_session_lock, get_session

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.models.protego.recommendations import ObjectRecommendation
from app.models.graph import SVGPlot

from app.ssm.cyberkit4sme.bg_create_graph import bg_create_attack_path

from fastapi.logger import logger

router = APIRouter(tags=['Cyberkit4SME'])


@router.get("/models/{model_webkey}/path_plot",
            #response_model=SVGPlot,
            responses={
                404: {"description": "Item not found"},
                },
            status_code=status.HTTP_200_OK)
async def create_plot(model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm: SSMClient = Depends(get_ssm_base),
                      risk_mode: str = 'CURRENT',
                      export_format: str = 'svg',
                     ):
    """
    Create an attack path plot

    :param str model_webkey: the webkey of the SSM model corresponding to the live system

    :param str risk_mode: specify the SSM risk model calculation, i.e. CURRENT|FUTURE, default is CURRENT

    :param str export_format: specify the output format of the graph, default format is SVG, other supported formats are PDF, PNG

    :return: SVG plot document
    """

    logger.info(f"create attack path plot {model_webkey}")


    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create calc-risk job")

    vjob_id = str(vjob.id)
    logger.info(f"calc risks and recommendations job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.info(f"starting bg job")

    try:
        #bg_tasks.add_task(bg_shortest_path_recommendation, model_webkey, vjob_id,
        #        db_client, ssm, risk_mode, retain_cs_changes)

        svg_plot = await bg_create_attack_path(model_webkey, vjob_id, db_client, ssm,
                risk_mode, export_format)

        #svg_plot = {"svg": "empty"}  # await get_plot(db_client, job_id, rec_id)

    except Exception as e:
        logger.error("Exception in create_plot endpoint: %s\n" % e)
        logger.debug(f"attack path plot was not created for {model_webkey}")
        raise HTTPException(status_code=404, detail=f"No attack path plot created for {model_webkey}")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_client, vjob_id)


    #return svg_plot
    #return Response(content=svg_plot, media_type="application/xml")

    return PlainTextResponse(svg_plot, media_type="image/svg+xml")



