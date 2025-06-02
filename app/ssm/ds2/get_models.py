##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2025
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre of Gamma House, Enterprise Road,
## Chilworth Science Park, Southampton, SO16 7NS, UK.
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
##      Created Date :          2025-05-28
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

import re
from app.models.ds2.advice import AdviceInput, DataType
from fastapi.logger import logger
import json

from app.ssm.ssm_client import SSMClient

def load_models():
    # Path for system models definition file
    file_path = 'models.json'

    # Load system models (basic info) from JSON file
    with open(file_path, 'r', encoding='utf-8') as file:
        models_json = json.load(file)

    # Print the loaded data
    print(models_json)

    return models_json

def select_model(advice_input: AdviceInput, models, ssm_client: SSMClient):
    logger.info("Selecting model...")

    logger.info(f"deployment_type: {advice_input.deployment_type}")
    logger.info(f"data_type: {advice_input.data_type}")
    logger.info(f"known_migrations: {advice_input.known_migrations}")
    logger.info(f"user_priorities: {advice_input.user_priorities}")

    # Select models with specific deployment_type
    selected_models = select_deployment_models(advice_input.deployment_type, models)
    
    # Select models with specific data_type
    selected_models = select_data_type_models(advice_input.data_type, selected_models, ssm_client)

    logger.info(f"Final selected models: {selected_models}")

    # Here, we should ideally end up with one selected model
    if len(selected_models) > 0:
        if len(selected_models) >= 1:
            selected_model = selected_models[0]

            if len(selected_models) > 1:
                logger.warning(f"More than one model found: returning first one: {selected_model}")
            else:
                logger.info(f"Located single model: {selected_model}")

            return selected_model
    else:
        logger.warning("No models found for criteria")
 
def select_deployment_models(deployment_type, models):
    selected_models = []

    # Currently the deployment type (local/cloud) is contained in the name of the model
    # Name should also contain string "ds2"
    for model in models:
        name = model["name"]
        logger.info(f"Checking model: {name}...")
        if "ds2" in name:
            if deployment_type == "local" and "local" in name:
                logger.info(f"Found local model: {name}")
                selected_models.append(model)
            elif deployment_type == "cloud" and "cloud" in name:
                logger.info(f"Found cloud model: {name}")
                selected_models.append(model)
            else:
                logger.debug(f"Model not deployment_type: {deployment_type}")
        else:
            logger.debug(f"Model {name} is not a DS2 model")
        
    logger.info(f"Selected deployment models of type: {deployment_type}")
    logger.info(selected_models)

    if not selected_models:
        logger.debug(f"No models for deployment_type: {deployment_type}")

    return selected_models

def select_data_type_models(data_type: DataType, models, ssm_client: SSMClient):
    logger.info(f"Selecting models of data_type: {data_type}")
    logger.info(f"Specific data type: {data_type.classification}")

    # regex pattern for all Data assets
    data_pattern = ".*Data"

    # regex pattern for specific data type
    if data_type.classification == "generic" or data_type.classification == "" or data_type.classification == None:
        specific_data_pattern = ".*#Data"
    else:
        specific_data_pattern = ".*" + data_type.classification
    logger.info(f"specific_data_pattern: {specific_data_pattern}")

    selected_models = []

    for model in models:
        logger.info(f"Getting assets for model: {model["name"]} ({model["id"]})")

        # Get all assets for system model (via SSM)
        assets = ssm_client.get_assets(model["id"])

        # Select all data assets (i.e. that match data_pattern)
        data_assets = [a for a in assets if re.match(data_pattern, a.type)]

        # Select data assets of specified type
        specific_data_assets = [a for a in data_assets if re.match(specific_data_pattern, a.type, re.IGNORECASE)]
        logger.info(f"Specific data assets of type: {data_type.classification}")
        logger.info(specific_data_assets)

        # If data asset(s) found for spcific type, add the model to the list of selected models
        # (hopefully just one!)
        if specific_data_assets:
            logger.info(f"Selecting model: {model["name"]}")
            selected_models.append(model)

    return selected_models
    