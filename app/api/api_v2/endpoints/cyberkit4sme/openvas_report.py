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
##      Created Date :          2022-03-24
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////


from typing import Optional

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import status
from fastapi.responses import JSONResponse

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base

from app.crud.store import create_vjob
from app.crud.store import (acquire_session_lock, release_session_lock, update_status)

from app.ssm.cyberkit4sme.bg_vulnerability_report import bg_vulnerability_mapper, bg_ingest_openvas_reports

from app.core.config import OPENVAS_REPORT_FILE_LOCATION
from pathlib import Path as pathlibPath
from app.tools.finder import findFilesNewerThanFile, findFilesInLocation


from fastapi.logger import logger


router = APIRouter(tags=['Cyberkit4SME'])

#N.B. the following method is deprecated
"""
@router.post("/models/{model_webkey}/notify/openvas-report-old",
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 500: {"description": "Internal server error."},
                 },
             status_code=status.HTTP_200_OK)
async def notify_openvas_report(model_webkey: str = Path(..., title="ModelId webkey"),
                               db_client: AsyncIOMotorClient = Depends(get_database),
                               ssm: SSMClient = Depends(get_ssm_base),
                               ):
    " " "
    Keenai notifies the SSM Adaptor that a new OpenVAS scan report is available
    for reading and analysis.  Here, it is assumed that the SSM Adaptor is
    pre-configured with the location of the folder containing the OpenVAS
    report(s), and its filename (this is more secure than the report location
    being a parameter in the request).  This folder needs to be shared between
    the SSM and Keenaï using a docker bind volume.

    The SSM Adaptor reads and parses the OpenVAS file, creating an internal
    report object.  This OpenVAS report is analysed, to extract any identified
    vulnerablilities at one or more assets in the live system. These
    vulnerabilities are mapped internally to specific trustworthiness
    attributes (TWAs) on corresponding assets in the SSM system model, along
    with specific trustworthiness levels. The SSM Adaptor makes REST calls on
    the SSM service to update these identified TWAs.

    The call is BLOCKING.

    :param str model_webkey: the webkey of the SSM model corresponding to the
    live system

    :return "OK":
    " " "

    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create notify openvas report job")

    vjob_id = str(vjob.id)
    logger.info(f"notify openvas report job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.debug(f"starting notify openvas report blocking task: {vjob_id}")

    # Initialise map of asset metadata to asset (minimises unnecessary calls to find_ssm_asset)
    assetsDict = {}

    # Determine reports location
    files_location = OPENVAS_REPORT_FILE_LOCATION + "/" + model_webkey + "/"

    # Locate OpenVAS files in folder
    files = locate_openvas_files(files_location, model_webkey)

    # If any new reports are present, go over each report in turn, process the
    # vulnerabilties within them and update relevant SSM TWAs

    if len(files) > 0:
        logger.info(f"Found OpenVAS vulnerability report files: {files}")
        await bg_vulnerability_mapper(model_id=model_webkey, vjid=vjob_id,
                                      vuln_rep_file_names=files, vuln_type="OpenVAS",
                                      db_conn=db_client, ssm_client=ssm, assetsDict=assetsDict)

        logger.debug(f"finished notify OpenVAS report blocking task: {vjob_id}")

    else:
        logger.info("No new OpenVAS vulnerability report files found...")
        logger.info("releasing session lock")
        await release_session_lock(db_client, vjob_id)

    # Update timestamp of timestamp file so that only new vulnerability reports
    # will be detected at the next run
    pathlibPath(files_location+".timestamp").touch()

    return "OK"
"""

@router.post("/models/{model_webkey}/notify/openvas-report",
             responses={
                 404: {"description": "Item not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 500: {"description": "Internal server error."},
                 },
             status_code=status.HTTP_200_OK)
async def notify_openvas_report(model_webkey: str = Path(..., title="ModelId webkey"),
                               db_client: AsyncIOMotorClient = Depends(get_database),
                               ssm: SSMClient = Depends(get_ssm_base),
                               ):
    """
    Keenai notifies the SSM Adaptor that one or more new OpenVAS scan reports are available
    for reading and analysis.  Here, it is assumed that the SSM Adaptor is
    pre-configured with the location of the folder containing the OpenVAS
    report(s), and its filename (this is more secure than the report location
    being a parameter in the request). This folder needs to be shared between
    the SSM and Keenaï using a docker bind volume.

    The SSM Adaptor reads and parses the OpenVAS file(s), creating an internal OpenVAS
    report object. As opposed to the previous version of this method (openvas-report-old),
    this OpenVAS report object is now converted into a generic "state report", and submitted
    for injesting to the internal State Component.

    A separate endpoint (tbd) will be called to process state reports, extract any identified
    vulnerablilities at one or more assets in the live system, and adjust the SSM
    model accordingly.
    
    The call is BLOCKING.

    :param str model_webkey: the webkey of the SSM model corresponding to the
    live system

    :return list of state report ids (one per OpenVAS report), e.g.

    {
        "state_ids": [
            "650ac3aa6923a0baa19b21b3",
            "650ac3ab6923a0baa19b21b6"
        ],
        "message": "OK"
    }
    """

    vjob = await create_vjob(db_client, {"modelId": model_webkey})
    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create notify openvas report job")

    vjob_id = str(vjob.id)
    logger.info(f"notify openvas report job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db_client, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db_client, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                            detail="Resource is locked by another process, try again later.")

    logger.debug(f"starting notify openvas report blocking task: {vjob_id}")

    # Initialise map of asset metadata to asset (minimises unnecessary calls to find_ssm_asset)
    assetsDict = {}

    # Determine reports location
    files_location = OPENVAS_REPORT_FILE_LOCATION + "/" + model_webkey + "/"

    # Locate OpenVAS files in folder
    files = locate_openvas_files(files_location, model_webkey)

    # If any new reports are present, go over each report in turn, process the
    # vulnerabilties within them and update relevant SSM TWAs

    message = "OK"

    if len(files) > 0:
        logger.info(f"Found OpenVAS vulnerability report files: {files}")
        state_ids = await bg_ingest_openvas_reports(model_id=model_webkey, vjid=vjob_id,
                                      vuln_rep_file_names=files, vuln_type="OpenVAS",
                                      db_conn=db_client, ssm_client=ssm, assetsDict=assetsDict)
        logger.info(f"State report ids: {state_ids}")

        logger.debug(f"finished notify OpenVAS report blocking task: {vjob_id}")
    else:
        message = "No new OpenVAS vulnerability report files found"
        logger.info(f"{message}")
        state_ids = []
        logger.info("releasing session lock")
        await release_session_lock(db_client, vjob_id)

    # Update timestamp of timestamp file so that only new vulnerability reports
    # will be detected at the next run
    pathlibPath(files_location+".timestamp").touch()

    # Return id(s) of the new state report(s)
    return JSONResponse({"state_ids": state_ids, "message": message})

def locate_openvas_files(files_location: str, model_webkey: str):
    logger.info(f"locate_openvas_files for model {model_webkey}")

    # Find all files after last time stamp
    timestamp_file = pathlibPath(files_location+".timestamp")
    if timestamp_file.is_file():
        files = findFilesNewerThanFile(files_location, files_location+".timestamp")
    else:
        files = findFilesInLocation(files_location)

    return files
