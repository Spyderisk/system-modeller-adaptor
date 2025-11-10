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

import io

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from ssmclientlib.exceptions import ApiException
from fastapi.logger import logger
from app.ssm.ds2.external_reporting import invoke_reporting

router = APIRouter(tags=['DS2'])

from fastapi import File, UploadFile

@router.post("/ds2/{auth_key}/get-report",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_202_ACCEPTED)
async def get_report(
        file: UploadFile = File(...),
        auth_key: str = Path(..., title="Authentication key"),
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

