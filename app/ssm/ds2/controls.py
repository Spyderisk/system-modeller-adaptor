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
##      Created Date :          2025-06-12
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

import re
from fastapi.logger import logger
from app.models.ds2.advice import AdviceInput
from app.ssm.ssm_client import SSMClient

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"

def update_control_sets(advice_input: AdviceInput, model_webkey, ssm_client: SSMClient):
    logger.info(f"Getting control sets for model: {model_webkey}")
    known_mitigations = advice_input.known_mitigations

    # Get all control sets
    control_sets = ssm_client.get_system_controlsets(model_webkey)

    # Get all domain controls
    controls = ssm_client.get_domain_controls(model_webkey)

    # Get all assets
    assets_dict = ssm_client.get_system_assets(model_webkey)

    # Create list of simplified control set data
    cs_list = []
    for cs in control_sets.values():
        c = controls[cs.control]
        cs_list.append({'uri': cs.uri, 'label': c.label, 'locatedAt': cs.located_at, 
                        'asset_label':assets_dict[cs.located_at].label, 'proposed': cs.proposed})

    # Select first mitigation (TODO: loop through them)
    known_mitigation = known_mitigations[0]
    logger.info(f"known_mitigation: {known_mitigation}")

    # Create regex pattern, based on searching for known_mitigation string in the CS label
    cs_pattern = ".*" + known_mitigation
    logger.info(f"cs_pattern: {cs_pattern}")

    # Selection of control sets, according to input criteria
    selected_cs = [cs for cs in cs_list if re.match(cs_pattern, cs['label'], re.IGNORECASE)]
    logger.info(f"Selected control sets: {selected_cs}")

    cs_uris = []
    for cs in selected_cs:
        cs_uris.append(URI_PREFIX + cs['uri'])

    # Set selected controls to proposed
    cs_update = {'controls': cs_uris, 'proposed': True, 'workInProgress': False}
    logger.info("Updating controls..")
    logger.debug(f"{cs_update}")

    for cs in selected_cs:
        logger.info(f"CS: {cs['label']} at {cs['asset_label']} -> {True}")

    ssm_client.update_controls(model_webkey, cs_update)
    logger.info("Done")

    return selected_cs

def revert_control_sets(model_webkey, selected_cs, ssm_client: SSMClient):
    logger.info(f"Reverting control sets for model: {model_webkey}")
    logger.debug(f"Selected control sets: {selected_cs}")

    # Get all assets
    assets_dict = ssm_client.get_system_assets(model_webkey)

    for cs in selected_cs:
        cs['uri'] = URI_PREFIX + cs['uri']
        asset_uri = cs['locatedAt']
        asset = assets_dict[asset_uri]
        logger.info(f"CS: {cs['label']} at {cs['asset_label']} -> {cs['proposed']}")
        ssm_client.update_control_for_asset(model_webkey, asset.id, cs)
