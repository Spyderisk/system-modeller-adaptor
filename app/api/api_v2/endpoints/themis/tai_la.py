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
##      Created By :            Samuel M. Senior
##      Created Date :          2025-11-19
##      Created for Project :   THEMIS
##
##///////////////////////////////////////////////////////////////////////

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi.responses import JSONResponse
from fastapi import status
from fastapi.logger import logger

from app.db.mongodb import AsyncIOMotorClient, get_database

from app.ssm.themis.tai_la_internal import get_tai_la_results, process_characteristics_results, apply_characteristics_results, run_risk_calc, revert_TWA_level


router = APIRouter(tags=['THEMIS'])

@router.get("/themis/{auth_key}/notify/tai_lifecycle_actuator",
             responses={
                 404: {"description": "Model not found"},
                 423: {"description": "Resource locked, by another process try again later."},
                 500: {"description": "Internal server error."},
                 },
             status_code=status.HTTP_200_OK)
async def tai_la(
        auth_key: str = Path(..., title="Auth key")
        ):

    logger.info(f"Parse tia_la report notification for auth_key: {auth_key}")

    characteristics_results = get_tai_la_results(user_id=5263452367)
    characteristics_results = process_characteristics_results(characteristics_results)
    changes = apply_characteristics_results(characteristics_results)
    run_risk_calc()
    revert_TWA_level()

    return changes
