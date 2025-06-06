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
from app.ssm.ds2.impact import apply_impact_levels
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

        # First, load system model list from JSON file
        # N.B. We cannot query the SSM directly without being authenticated
        models = load_models()

        for model in models:
            logger.info(f"{model["name"]}: {model["id"]}")

        # Select a system model (template) according to the input criteria
        selected_model = select_model(advice_input, models, ssm_client)
        logger.info(f"Selected model: {selected_model}")
        model_webkey = selected_model["id"]

        # Identify relevant misbehaviour sets to apply raised impact level
        apply_impact_levels(advice_input, model_webkey, ssm_client)
        
        # Get basic model info
        model_info = ssm_client.get_model_info(model_webkey)

        # Check that model exists and is validated
        logger.info(f"Model info: {model_info}")
        assert (model_info is not None)
        assert (model_info.valid)

        # Check if risks are valid (usually not at this point)
        # If not, run the risk calculation
        logger.info(f"risk_levels_valid: {model_info.risk_levels_valid}")
        force_rc = True
        logger.info(f"force_rc: {force_rc}")

        if force_rc or not model_info.risk_levels_valid:
            if not model_info.risk_levels_valid:
                logger.info("Risks invalid - recalculating...")
            elif force_rc:
                logger.info("Recalculating risks anyway...")
            risk_calc_response = ssm_client.calculate_runtime_risk_fast(model_webkey, "FUTURE", True)
            assert (risk_calc_response is not None)
            model = risk_calc_response.model
            assert (model is not None)

            # Get all risk levels from the risk calc response
            levels = risk_calc_response.levels
            assert (levels is not None)
            risk_levels = levels['riLevels']
            logger.info(f"Risk levels: {risk_levels}")

            # Get or define acceptable risk level
            acceptable_risk_level_uri = 'domain#RiskLevelMedium' #TODO: get from config
            acceptable_risk_level = risk_levels[acceptable_risk_level_uri]
            logger.info(f"Acceptable risk level: {acceptable_risk_level}")

            # Log system model details, including name, risk, etc
            logger.info(f"Risk calc model info: {model}")
            risk_level = risk_levels[model.risk]
            logger.info(f'"{model.label}" has risk uri: {model.risk}')
            logger.info(f"Risk level: {risk_level}")

            # Check if system model risk value is acceptable
            if risk_level.level_value > acceptable_risk_level.level_value:
                logger.info("Model risk value is not acceptable")
            else:
                logger.info("Model risk value is acceptable")

            return model
        else:
            logger.info("Risks are currently valid")
            logger.info(f"Model info: {model_info}")
            return model_info

        logger.info("Advice completed")
    except Exception as e:
        logger.error("Exception in getadvice endpoint: %s\n" % e)
        raise HTTPException(status_code=404, detail=f"No advice available for {auth_key}")
