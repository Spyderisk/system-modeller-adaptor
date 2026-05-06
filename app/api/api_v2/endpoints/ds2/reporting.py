##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2025
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
##      Created Date :          2025-11-07
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi.responses import JSONResponse
from fastapi import status
from fastapi.responses import FileResponse
from fastapi.responses import StreamingResponse

from pydantic import HttpUrl

from fastapi import BackgroundTasks

import shutil
import io

from pathlib import Path as plibPath

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from ssmclientlib.exceptions import ApiException
from fastapi.logger import logger
from app.ssm.ds2.external_reporting import invoke_reporting_job
from app.models.ds2.reporting import ReportingMessage
from app.crud.store_reporting import store_reporting, get_reporting

router = APIRouter(tags=['Reporting'])

from fastapi import File, UploadFile

@router.post("/ssmtools/reporting/create-report-from-url",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def create_report_from_url(
        target_url: HttpUrl,
        iso_standard: str,
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Generate a system model risk report from a Spyderisk system model URL.

    This endpoint takes a system model URL as input, and returns the
    generated CSV risk report as a downloadable file.

    The system model URL can be found in the Spyderisk Dashboard by clicking
    the model's **Share Model** icon and copying the *Edit Access* or
    *View-only* Access URI. Trailing path segments such as `/edit` or `/read`
    may be included, however, the report tool will remove these automatically,
    if present.

    Parameters
    ----------
    target_url : URL, the full Spyderisk system model URL.

    iso_standard : ISO standard for output format (27001 or 14971).

    Returns
    -------
    StreamingResponse
        A streaming HTTP response containing the generated CSV risk report,
        with the "Content-Disposition" header set for file download.
    """

    logger.info("REPORTING tool URL")
    reporting_msg = ReportingMessage()
    reporting_msg.nq_filename = str(target_url)
    reporting_msg.iso = iso_standard
    logger.debug(f"REPORTING: {reporting_msg}")

    vjob_id = await store_reporting(db_client, reporting_msg)
    if not vjob_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create reportig job")

    vjob_id = str(vjob_id)
    logger.info(f"reporting job, {vjob_id}")

    status = await invoke_reporting_job(db_client, vjob_id, reporting_msg)
    csv_stream = io.BytesIO(status['output_csv'].encode("utf-8"))

    return StreamingResponse(
            csv_stream,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report.csv"}
        )


@router.post("/ssmtools/reporting/create-report",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def create_report(
        iso_standard: str,
        nq_file: UploadFile = File(...),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Generate a system model risk report from an uploaded Spyderisk system model
    NQ file.

    This endpoint takes a Spyderisk system model NQ file as input, and returns
    a CSV-formatted risk report as a downloadable file.

    Parameters
    ----------
    nq_file : UploadFile
        The Spyderisk system model NQ file provided by the user.

    iso_standard : ISO standard for output format (27001 or 14971).

    Returns
    -------
    StreamingResponse
        A streaming HTTP response containing the generated CSV risk report,
        with the "Content-Disposition" header set for file download.
    """

    reporting_msg = ReportingMessage()
    reporting_msg.nq_filename = nq_file.filename
    reporting_msg.iso = iso_standard
    logger.debug(f"REPORTING: {reporting_msg}")

    vjob_id = await store_reporting(db_client, reporting_msg)
    if not vjob_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create reportig job")

    vjob_id = str(vjob_id)
    logger.info(f"reporting job, {vjob_id}")

    # store input file
    tmp_path = plibPath(reporting_msg.tempdir) / nq_file.filename
    with open(tmp_path, "wb") as buffer:
        shutil.copyfileobj(nq_file.file, buffer)

    #status = invoke_reporting(nq_file, reporting_msg)
    status = await invoke_reporting_job(db_client, vjob_id, reporting_msg)
    csv_stream = io.BytesIO(status['output_csv'].encode("utf-8"))

    return StreamingResponse(
            csv_stream,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report.csv"}
        )


@router.post("/ssmtools/reporting/create-report-from-url-async",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def create_report_from_url_async(
        target_url: HttpUrl,
        iso_standard: str,
        background_tasks: BackgroundTasks = None,
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Generate a system model risk report from a Spyderisk system model URL.
    This is an asynchronous call.

    This endpoint takes a system model URL as input, and returns the ID of the
    reporting tool job. The job ID should be used to monitor the status of the
    reporting job, as well as to download the output of the report.

    The system model URL can be found in the Spyderisk Dashboard by clicking
    the model's **Share Model** icon and copying the *Edit Access* or
    *View-only* Access URI. Trailing path segments such as `/edit` or `/read`
    may be included, however, the report tool will remove these automatically,
    if present.

    Parameters
    ----------
    target_url : URL, the full Spyderisk system model URL.

    iso_standard : ISO standard for output format (27001 or 14971).

    Returns
    -------
    job status : the ID of the background reporting job.

    """

    logger.info("REPORTING tool URL async")
    reporting_msg = ReportingMessage(jtype="ASYNC")
    reporting_msg.nq_filename = str(target_url)
    reporting_msg.iso = iso_standard
    logger.debug(f"REPORTING: {reporting_msg}")

    vjob_id = await store_reporting(db_client, reporting_msg)
    if not vjob_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create reportig job")

    vjob_id = str(vjob_id)
    logger.info(f"reporting job, {vjob_id}")

    # invoke the backgournd external job
    background_tasks.add_task(invoke_reporting_job, db_client, vjob_id, reporting_msg)
    logger.debug("RETURN from async job?")

    return {"rjob_id": vjob_id, "status": reporting_msg.status}


@router.post("/ssmtools/reporting/create-report-async",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def create_report_async(
        iso_standard: str,
        nq_file: UploadFile = File(...),
        background_tasks: BackgroundTasks = None,
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """

    Generate a system model risk report from an uploaded Spyderisk system model
    NQ file asynchronous call.

    This endpoint takes a Spyderisk system model NQ file as input, and returns
    ID of the reporting tool job. The job ID should be used to monitor the
    status of the reporting job, as well as to download the output of the
    report.

    Parameters
    ----------
    nq_file : UploadFile
        The Spyderisk system model NQ file uploaded by the user.

    iso_standard : ISO standard for output format (27001 or 14971).

    Returns
    -------
    job status : the ID of the background reporting job.
    """

    logger.info("REPORTING tool async")
    reporting_msg = ReportingMessage(jtype="ASYNC")
    reporting_msg.nq_filename = nq_file.filename
    reporting_msg.iso = iso_standard
    logger.debug(f"REPORTING: {reporting_msg}")

    vjob_id = await store_reporting(db_client, reporting_msg)
    if not vjob_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Failed to create reportig job")

    vjob_id = str(vjob_id)
    logger.info(f"reporting job, {vjob_id}")

    # store input file
    tmp_path = plibPath(reporting_msg.tempdir) / nq_file.filename
    with open(tmp_path, "wb") as buffer:
        shutil.copyfileobj(nq_file.file, buffer)


    # invoke the backgournd external job
    background_tasks.add_task(invoke_reporting_job, db_client, vjob_id, reporting_msg)
    logger.debug("RETURN from async job?")

    return {"rjob_id": vjob_id, "status": reporting_msg.status}


@router.get("/ssmtools/reporting/status/{report_id}",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def get_report_status(
        report_id: str,
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Get the status of an asynchronous risk reporting job.

    This endpoint takes the risk reporting job ID, and returns the current
    status of the associated background reporting job.

    Parameters
    ----------
    report_id : the risk reporting job identifier

    Returns
    -------
    job status : the current status of the background reporting job.
    """

    status = await get_reporting(db_client, report_id)
    logger.debug(f"GET REPORTING status: {status}")

    return {"jobid": report_id, "status": status.status}


@router.get("/ssmtools/reporting/download/{report_id}",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def get_report_download(
        report_id: str,
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Download the generated risk reporting tool output as a CSV file.

    This endpoint takes the risk reporting job ID, and returns the completed
    risk report file as a `FileResponse`.

    Parameters
    ----------
    report_id : the risk reporting job id

    Returns
    -------
    FileResponse
        A file response containing the CSV report with the
        "Content-Disposition" header set for file download.
    """

    status = await get_reporting(db_client, report_id)
    logger.debug(f"DOWNLOAD REPORTING status: {status}")

    if not status:
        return JSONResponse({"error": "Job not found"}, status_code=404)

    if status.status != "finished":
        logger.debug(f"Job is not complete, {status.status}")
        return JSONResponse({"status": status.status})

    logger.debug("job completed, preparing download")

    output_file = plibPath(status.output_filename)
    if not output_file.exists():
        return JSONResponse({"error": "Output file missing"}, status_code=500)

    return FileResponse(output_file, media_type="text/csv", filename="report.csv")

