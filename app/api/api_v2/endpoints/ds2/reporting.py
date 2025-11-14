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

from fastapi import BackgroundTasks

import shutil
import io

from pathlib import Path as plibPath

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from ssmclientlib.exceptions import ApiException
from fastapi.logger import logger
from app.ssm.ds2.external_reporting import invoke_reporting, run_reporting_job
from app.models.ds2.reporting import ReportingMessage
from app.crud.store_reporting import store_reporting, get_reporting

router = APIRouter(tags=['Reporting'])

from fastapi import File, UploadFile

@router.post("/tools/reporting/create-report",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def create_report(
        file: UploadFile = File(...),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Generate a system model report from an uploaded NQ file.

    This endpoint takes a system model NQ file as input, and returns the
    generated CSV report as a downloadable file.

    Parameters
    ----------
    file : UploadFile
        The system model NQ file uploaded by the user.

    Returns
    -------
    StreamingResponse
        A streaming response containing the CSV report with the
        "Content-Disposition" header set for file download.
    """

    status = invoke_reporting(file)
    csv_stream = io.BytesIO(status['output_csv'].encode("utf-8"))

    #return {"jobid": vjob_id, "status": vjob_status}

    #return FileResponse(
    ##        path="test.csv",
    #        media_type="text/csv",
    #        filename="report.csv"
    #    )

    return StreamingResponse(
            csv_stream,
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report.csv"}
        )


@router.post("/tools/reporting/create-report_async",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def create_report_async(
        nq_file: UploadFile = File(...),
        background_tasks: BackgroundTasks = None,
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):

    """
    Generate a system model report from an uploaded NQ file asynchronous call.

    This endpoint takes a system model NQ file as input, and returns the
    generated CSV report as a downloadable file.

    Parameters
    ----------
    nq_file : UploadFile
        The system model NQ file uploaded by the user.

    Returns
    -------
    StreamingResponse
        A streaming response containing the CSV report with the
        "Content-Disposition" header set for file download.
    """

    logger.info("REPORTING tool async")
    #reporting_msg = ReportingMessage({"nq_filename": file.filename})
    reporting_msg = ReportingMessage()
    reporting_msg.nq_filename = nq_file.filename
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
    background_tasks.add_task(run_reporting_job, db_client, nq_file, vjob_id, reporting_msg)
    logger.debug("RETURN from async job?")

    return {"rjob_id": vjob_id, "status": reporting_msg.status}


@router.get("/tools/reporting/status/{report_id}",
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
    Generate a system model report from an uploaded NQ file asynchronous call.

    This endpoint takes a system model NQ file as input, and returns the
    generated CSV report as a downloadable file.

    Parameters
    ----------
    file : UploadFile
        The system model NQ file uploaded by the user.

    Returns
    -------
    StreamingResponse
        A streaming response containing the CSV report with the
        "Content-Disposition" header set for file download.
    """

    status = await get_reporting(db_client, report_id)
    logger.debug(f"GET REPORTING status: {status}")

    return {"jobid": report_id, "status": status.status}


@router.get("/tools/reporting/download/{report_id}",
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
    Generate a system model report from an uploaded NQ file asynchronous call.

    This endpoint takes a system model NQ file as input, and returns the
    generated CSV report as a downloadable file.

    Parameters
    ----------
    file : UploadFile
        The system model NQ file uploaded by the user.

    Returns
    -------
    StreamingResponse
        A streaming response containing the CSV report with the
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

