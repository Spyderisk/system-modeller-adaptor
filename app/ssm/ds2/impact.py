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
##      Created Date :          2025-06-03
##      Created for Project :   DS2
##
##///////////////////////////////////////////////////////////////////////

import re

from app.models.ds2.advice import AdviceInput
from app.ssm.ssm_client import SSMClient
from fastapi.logger import logger

from ssmclientlib.models.level import Level
from ssmclientlib.models.misbehaviour_set import MisbehaviourSet

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"

# Apply raised impact levels to misbehaviour sets identified by input criteria
# Return the original selected misbehaviour sets
def apply_impact_levels(advice_input: AdviceInput, model_webkey, ssm_client: SSMClient):
    selected_misbehaviour_sets = select_misbehaviour_sets(advice_input, model_webkey, ssm_client)
    logger.info(f"Selected misbehaviour sets: {selected_misbehaviour_sets}")

    # Set any selected misbehaviour sets to "Very High" impact. TODO: we may want to configure this
    new_impact_level_uri = URI_PREFIX + "domain#ImpactLevelVeryHigh"
    new_impact_level = Level(uri=new_impact_level_uri)

    for ms in selected_misbehaviour_sets:
        ms_uri = URI_PREFIX + ms.uri
        ms_id = "1234" # id not available here, but does not seem to be used on the server side!
        logger.info(f"Updating impact for {ms_uri}, {ms_id}, {new_impact_level}")
        # Create updated MisbehaviourSet, with the basic required fields
        updated_ms = MisbehaviourSet(uri=ms_uri, id=ms_id, impactLevel=new_impact_level)
        logger.info(f"Updated ms: {updated_ms}")
        ssm_client.update_misbehaviour_impact(model_webkey, updated_ms)

    return selected_misbehaviour_sets

def revert_impact_levels(model_webkey, selected_misbehaviour_sets, ssm_client: SSMClient):
    logger.info("Reverting impact levels on selected misbehaviour sets")
    for ms in selected_misbehaviour_sets:
        ms_uri = URI_PREFIX + ms.uri
        ms_id = "1234" # id not available here, but does not seem to be used on the server side!

        orig_impact_level_uri = URI_PREFIX + ms.impact_level
        orig_impact_level = Level(uri=orig_impact_level_uri)

        logger.info(f"Reverting impact for {ms_uri}, {ms_id}, {orig_impact_level}")
        # Create MisbehaviourSet, with the basic required fields
        updated_ms = MisbehaviourSet(uri=ms_uri, id=ms_id, impactLevel=orig_impact_level)
        logger.info(f"Reverted ms: {updated_ms}")
        ssm_client.update_misbehaviour_impact(model_webkey, updated_ms)

# Select appropriate misbehaviour sets according to input criteria
def select_misbehaviour_sets(advice_input: AdviceInput, model_id, ssm_client: SSMClient):
    misbehaviour_sets_dict = ssm_client.get_system_misbehavioursets(model_id)
    misbehaviour_sets = list(misbehaviour_sets_dict.values())

    misbehaviours_dict = ssm_client.get_domain_misbehaviours(model_id)

    assets_dict = ssm_client.get_system_assets(model_id)
    logger.info(f"assets_dict: {assets_dict}")

    # Get user priorities, then convert to misbehaviour 
    user_priorities = advice_input.user_priorities
    logger.info(f"user_priorities: {user_priorities}")

    # Select first priority (TODO: loop through them)
    user_priority = user_priorities[0]
    logger.info(f"user_priority: {user_priority}")

    # Create regex pattern, based on searching for user_priority string in the MS URI
    ms_pattern = ".*" + user_priority
    logger.info(f"ms_pattern: {ms_pattern}")

    # Initial selection of misbehaviour sets, according to input criteria
    selected_ms = [ms for ms in misbehaviour_sets if re.match(ms_pattern, ms.uri, re.IGNORECASE)]
    logger.info(f"Initially selected misbehaviour_sets: {selected_ms}")

    selected_misbehaviour_sets = []

    # Finally filter out any misbehaviour sets that are not visible, or located at inferred assets
    logger.info("Selecting misbehaviour sets:")
    for ms in selected_ms:
        m = misbehaviours_dict[ms.misbehaviour]
        if not m.visible:
            continue
        asset_uri = ms.located_at
        asset = assets_dict[asset_uri]
        if not asset.asserted:
            continue
        logger.info(f"{m.label} at {asset.label}")
        selected_misbehaviour_sets.append(ms)

    return selected_misbehaviour_sets
