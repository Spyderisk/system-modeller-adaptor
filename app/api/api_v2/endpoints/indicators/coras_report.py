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

from app.ssm.indicators.coras_internal_report import bg_process_coras_report, bg_process_coras_indicator

from app.crud.store import create_vjob
from app.crud.store import (acquire_session_lock, release_session_lock, update_status)

from fastapi.logger import logger


router = APIRouter(tags=['Notifications'])


@router.post("/models/{model_webkey}/notify/coras-report",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def notify_coras_report(
                      coras_report: AiraReport,
                      model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    Test CorasReport

    :param CorasReport:

    :return: state report id
    """

    logger.info(f"Parse Coras report notification for model: {model_webkey}")

    vjob_id = None
    lock_acquired = False

    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")

        vjob = await create_vjob(db_client, {"ssm_model_id": model_webkey})
        if not vjob:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Failed to create job")

        vjob_id = str(vjob.id)

        # acquire session lock
        lock_acquired = await acquire_session_lock(db_client, vjob_id)

        if not lock_acquired:
            # update status of job as REJECTED
            await update_status(db_client, vjob_id, "REJECTED")
            logger.debug("Failed to acquire session lock return 423")
            raise HTTPException(status_code=status.HTTP_423_LOCKED,
                                detail="Resource is locked.")

        state_id = await bg_process_coras_report(model_webkey, coras_report, ssm_client, db_client)

        logger.info(f"Created state report: {state_id}")

        return JSONResponse({"status": "success", "report_state_id": state_id})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No state report created for {model_webkey}")
    finally:
        if lock_acquired and vjob_id:
            logger.info("Releasing session lock")
            await release_session_lock(db_client, vjob_id)


@router.post("/models/{model_webkey}/notify/coras-indicator",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def apply_coras_indicator(
                      coras_report: AiraReport,
                      model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    Test CorasReport

    :param CorasReport:

    :return: ?
    """

    logger.info(f"Parse Coras report notification for model: {model_webkey}")

    vjob_id = None
    lock_acquired = False

    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")

        vjob = await create_vjob(db_client, {"ssm_model_id": model_webkey})
        if not vjob:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                                detail="Failed to create job")

        vjob_id = str(vjob.id)

        # acquire session lock
        lock_acquired = await acquire_session_lock(db_client, vjob_id)

        if not lock_acquired:
            # update status of job as REJECTED
            await update_status(db_client, vjob_id, "REJECTED")
            logger.debug("Failed to acquire session lock return 423")
            raise HTTPException(status_code=status.HTTP_423_LOCKED,
                                detail="Resource is locked.")

        result = await bg_process_coras_indicator(model_webkey, aira_report, ssm_client, db_client)

        if not result:
            raise HTTPException(status_code=500, detail=f"failed to apply Coras indicator")

        logger.info(f"Coras indicator processed successfully")

        return JSONResponse({"status": "success", "result": result})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No weakness applied for {model_webkey}")
    finally:
        if lock_acquired and vjob_id:
            logger.info("Releasing session lock")
            await release_session_lock(db_client, vjob_id)


