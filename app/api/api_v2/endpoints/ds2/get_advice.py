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
##      Created By :            Ken Meacham
##      Created Date :          2025-05-01
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

from fastapi import APIRouter, Depends, Path, HTTPException
from fastapi.responses import JSONResponse
from fastapi import status
from app.db.mongodb import AsyncIOMotorClient, get_database
from app.models.ds2.advice import AdviceInput
from app.ssm.ds2.get_models import load_models, select_model
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from ssmclientlib.exceptions import ApiException
from fastapi.logger import logger

router = APIRouter(tags=['DS2'])

@router.post("/ds2/{auth_key}/get-advice",
            responses={
                500: {"description": "Internal server error."},
                },
            status_code=status.HTTP_200_OK)
async def get_advice(
                      advice_input: AdviceInput,
                      auth_key: str = Path(..., title="Authentication key"),
                      db_client: AsyncIOMotorClient = Depends(get_database),
                      ssm_client: SSMClient = Depends(get_ssm_base),
                     ):
    """
    This method provides general advice about risks relating to the deployment phase of DS2 modules.

    The DS2 chatbot calls this POST method with a specification of the deployment scenario as input (JSON).

    The auth_key is a secret key, agreed with the client, used only for security purposes.
    """

    logger.info(f"Get advice for auth_key: {auth_key}")

    try:
        logger.info(f"Advice input: \n{advice_input}")

        models = load_models()

        for model in models:
            logger.info(f"{model["name"]}: {model["id"]}")

        selected_model = select_model(advice_input, models, ssm_client)

        logger.info(f"Selected model: {selected_model}")
        
        logger.info("Advice completed")
    except Exception as e:
        logger.error("Exception in getadvice endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No advice available for {auth_key}")

    # For now, return the selected model details
    # (later we will return the actual advice response)
    return JSONResponse(selected_model)

