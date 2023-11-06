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
##      Created Date :          2023-09-13
##      Created for Project :   Cyberkit4SME
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
from ssm_api_client.exceptions import ApiException

from app.models.state_report import StateReportMessage, StateReportInfo
from app.crud.store_state_report import get_stored_state_report, get_all_reports
from app.crud.store_state_report import store_state_report, remove_state_report, remove_state_reports

from app.ssm.cyberkit4sme.bg_process_state_reports import bg_process_state_reports

from fastapi.logger import logger


router = APIRouter(tags=['Cyberkit4SME'])


@router.post("/models/{model_webkey}/states",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def state_report(
                      state_report_message: StateReportMessage,
                      model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    Test StateReportMessage

    :param state report message:

    :return: state report id
    """

    logger.info(f"Create state report for model: {model_webkey}")

    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        assert (model is not None)

        state_id = await store_state_report(db_client, model_webkey, state_report_message)
        logger.info(f"Created state report: {state_id}")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No state report created for {model_webkey}")

    return JSONResponse({"state_id": state_id})

@router.get("/models/{model_webkey}/states",
            response_model=List[StateReportInfo],
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def list_state_reports(
                      model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    List state reports for given model webkey

    :return: list of state report ids
    """

    logger.info(f"List state reports for model: {model_webkey}")

    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        assert (model is not None)

        state_reports = await get_all_reports(db_client, model_webkey)
        logger.info(f"Located {len(state_reports)} state reports")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No state reports available for {model_webkey}")

    return state_reports

@router.get("/models/{model_webkey}/states/{state_id}",
            response_model=StateReportMessage,
            responses={
                404: {"description": "Model not found"},
                },
            status_code=status.HTTP_200_OK)
async def download_state_report(state_id: str = Path(..., title="Download state report"),
                                   model_webkey: str = Path(..., title="Model webkey"),
                                   db_client: AsyncIOMotorClient = Depends(get_database),
                                   ssm_client: SSMClient = Depends(get_ssm_base),
                                ):
    """
    Get state report

    :param state_id: The ID of the stored state report

    :return: state report message document
    """

    logger.info(f"Download state report: {state_id} for model: {model_webkey}")
    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        assert (model is not None)

        state = await get_stored_state_report(db_client, state_id)
        logger.debug(f"DB state report: {state}, {type(state)}")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"Could not locate state report {state_id} for model {model_webkey}")

    return state

@router.delete("/models/{model_webkey}/states",
            responses={
                404: {"description": "Model not found"},
                },
            status_code=status.HTTP_200_OK)
async def delete_state_reports(
                                   model_webkey: str = Path(..., title="Model webkey"),
                                   db_client: AsyncIOMotorClient = Depends(get_database),
                                   ssm_client: SSMClient = Depends(get_ssm_base),
                              ):
    """
    Delete all state reports for a model

    :return: "OK"

    """

    logger.info(f"Delete state reports for model: {model_webkey}")
    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        assert (model is not None)

        deleted_count = await remove_state_reports(db_client, model_webkey)
        logger.debug(f"Deleted {deleted_count} state reports")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"Could not delete state reports for model {model_webkey}")

    return "OK"

@router.delete("/models/{model_webkey}/states/{state_id}",
            responses={
                404: {"description": "Model not found"},
                },
            status_code=status.HTTP_200_OK)
async def delete_state_report(state_id: str = Path(..., title="Delete state report"),
                                   model_webkey: str = Path(..., title="Model webkey"),
                                   db_client: AsyncIOMotorClient = Depends(get_database),
                                   ssm_client: SSMClient = Depends(get_ssm_base),
                             ):
    """
    Delete state report

    :param state_id: The ID of the stored state report to delete

    :return: "OK"

    """

    logger.info(f"Delete state report: {state_id} for model: {model_webkey}")
    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        assert (model is not None)

        deleted_count = await remove_state_report(db_client, state_id)
        logger.debug(f"Deleted {deleted_count} state reports")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"Could not locate state report {state_id} for model {model_webkey}")

    return "OK"

@router.post("/models/{model_webkey}/states/process",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def process_state_reports(
                      model_webkey: str = Path(..., title="Model webkey"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    Process state reports

    :return: int number of reports processed.
    """

    logger.info(f"Process state reports for model: {model_webkey}")

    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create process state report job")

    vjob_id = str(vjob.id)
    logger.info(f"process state report job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    try:
        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(model_webkey)
        assert (model is not None)

        reports = await bg_process_state_reports(model_webkey, vjob_id, ssm_client,  db_client)
        logger.debug(f"DB state reports processed: {reports}")
    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in processing state_report endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"Could not process state reports for {model_webkey}")

    return JSONResponse({"processed reports": reports})


