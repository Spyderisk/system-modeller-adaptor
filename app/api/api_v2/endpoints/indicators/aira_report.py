##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2023
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Highfield Campus, SO17 1BJ, UK.
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
##      Created Date :          2025-02-11
##      Created for Project :   NEMECYS
##
##///////////////////////////////////////////////////////////////////////

from typing import Optional, List

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import Response
from fastapi.responses import JSONResponse
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
from ssmclientlib.exceptions import ApiException

from app.models.indicators.aira_model import AiraReport

from app.crud.store_state_report import get_stored_state_report, get_all_reports
from app.crud.store_state_report import store_state_report, remove_state_report, remove_state_reports

from app.ssm.indicators.aira_internal_report import bg_process_aira_report

from fastapi.logger import logger


router = APIRouter(tags=['Notifications'])


@router.post("/models/{model_webkey}/notify/aira-report",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def notify_aira_report(
                      aira_report: AiraReport,
                      model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    Test AiraReport

    :param AiraReport:

    :return: state report id
    """

    logger.info(f"Parse Aira report notification for model: {model_webkey}")

    try:
        # Check whether the system model exists (via basic model info)
        #model = ssm_client.get_model_info(model_webkey)
        #assert (model is not None)

        #TODO parse Aira report and convert it to intenal state report ...

        state_report_message = await bg_process_aira_report(model_webkey, aira_report, ssm_client, db_client)

        state_id = 99  # await store_state_report(db_client, model_webkey, state_report_message)

        logger.info(f"Created state report: {state_id}")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No state report created for {model_webkey}")

    return JSONResponse({"state_id": state_id})

