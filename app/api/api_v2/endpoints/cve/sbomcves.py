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
##      Created Date :          2025-08-28
##      Created for Project :   TELEMETRY
##
##///////////////////////////////////////////////////////////////////////

from typing import List
from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi import Response
from fastapi.responses import JSONResponse
from fastapi import status
from app.db.mongodb import AsyncIOMotorClient, get_database
from app.models.cve.sbomcve import CVESBOM

from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from ssmclientlib.exceptions import ApiException
from fastapi.logger import logger

router = APIRouter(tags=['TELEMETRY'])

@router.post("/cve/{model_webkey}/sbomcve",
            responses={
                404: {"description": "Model not found"},
                423: {"description": "Resource locked, by another process try again later."},
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def sbomcve(
        sbomcve_list: List[CVESBOM],
        model_webkey: str = Path(..., title="Model webkey"),
        db_client: AsyncIOMotorClient = Depends(get_database),
        ssm_client: SSMClient = Depends(get_ssm_base),
        ):
    """
    REST POST to upload an SBOMCVE list

    :param sbomcve_list: List of SBOMCVE objects

    :return: 99
    """

    logger.info(f"Parsing SBOM CVE list for model: {model_webkey}")

    try:
        #TODO
        # Check whether the system model exists (via basic model info)
        ##model = ssm_client.get_model_info(model_webkey)
        ##assert (model is not None)

        # Check CVEs
        logger.debug(f"SBOMCVE has {len(sbomcve_list)}")
        for sbomcve in sbomcve_list:
            logger.debug(f"\tReceived CVE: {sbomcve}")

        state_id = 99  # await store_state_report(db_client, model_webkey, state_report_message)

        return JSONResponse({"status": "ok", "count": len(sbomcve_list)})

    except ApiException as api_ex:
        logger.info(f"API exception: model not found {api_ex}")
        raise HTTPException(status_code=api_ex.status, detail=f"Model not found")
    except Exception as e:
        logger.error("Exception in SBOM CVE endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No CVEs found for {model_webkey}")

