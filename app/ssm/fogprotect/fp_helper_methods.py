##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2021
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
##      Created Date :          2021-05-19
##      Created for Project :   FogProtect
##
##///////////////////////////////////////////////////////////////////////

from app.core.config import ACCEPTABLE_RISK_LEVEL, FP_DISABLEMENT_CONTROL, GET_ASSET_METADATA_FROM_VULN

from app.ssm.ssm_client import SSMClient
from ssm_api_client import Asset

from app.models.fogprotect.adaptation_coordinator.notification_models import ResultOfRiskCalculation
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.protego.recommendations import CurrentState
from app.models.risk import Risk, State

from fastapi.logger import logger

import re

"""
def set_tw_level_for_asset_vuln(ssm_client: SSMClient, model_id, asset, vuln, event_name):
    logger.info(f"Setting TW level for asset \"{asset.label}\"")
    logger.info(f"Vulnerability: {vuln}")

    #Deprecated, so set to None
    event_status = None

    set_tw_level_for_event(ssm_client, model_id, asset, event_name, event_status)

def set_tw_level_for_event(ssm_client: SSMClient, model_id, asset, event_name, event_status):

    logger.debug(f"event_name: {event_name}")
    logger.debug(f"event_status: {event_status}")
"""

def get_assets_for_event(ssm_client: SSMClient, modelId, event):
    if GET_ASSET_METADATA_FROM_VULN:
        """
        logger.info("Getting asset metadata from vulnerability")
        #Query SSM to locate asset with metadata from vulnerability
        assets = ssm_client.get_ssm_asset(modelId, 
            filename=vuln.filename
        )
        """

        #Here we might get all assets involved in a certain event, however to simplify we just use "true" - see below
        #event_value = event_name + ":" + vuln.filename
        #logger.info(f"Getting assets for event: {event_value}")

        event_value = "true"
        logger.info(f"Getting event assets")

        #Query SSM to locate asset with metadata from event type
        assets = ssm_client.get_ssm_asset(modelId, 
            event=event_value
        )
    else:
        logger.info("Getting asset metadata from object_to_identify")

        changes_made_to_as_is_model_list = event.changes_made_to_as_is_model
        changes_made_to_as_is_model = changes_made_to_as_is_model_list[0] #assume ony one for now
        #logger.debug(f"changes_made_to_as_is_model: {changes_made_to_as_is_model}")
        object_to_identify = changes_made_to_as_is_model.object_to_identify
        #logger.debug(f"object_to_identify: {object_to_identify}")

        #Query SSM to locate asset with metadata from object_to_identify
        assets = ssm_client.get_ssm_asset(modelId, 
            name=object_to_identify.name,
            type=object_to_identify.type,
            atid=object_to_identify.atid
        )

    n_assets = len(assets)
    logger.info(f"Located {n_assets} assets:");

    """
    if n_assets > 0:
        asset = assets[0]
        for a in assets: 
            logger.info(f"\"{a.label}\" ({a.id})")
        if n_assets > 1:
            logger.warn("Located multiple assets with same metadata - will select first..")

        #Set the TW level(s) for the asset in the SSM
        set_tw_level_for_asset_vuln(ssm_client, modelId, asset, vuln, event_name)
    else:
        if GET_ASSET_METADATA_FROM_VULN:
            raise Exception(f"No SSM asset found for vulnerability: {vuln}")
        else:
            raise Exception(f"No SSM asset found for object_to_identify: {object_to_identify}")
    """

    return assets

#Update TWAS or Controls on one or more assets, according to the asset metadata for specified event key
def update_multiple_twas_or_controls_for_assets(ssm_client: SSMClient, modelId, assets, event_key):
    logger.info(f"Filtering asset updates for event: {event_key}")

    for a in assets:
        identifier = []
        if a.metadata:
            for entry in a.metadata:
                identifier.append({"key": entry.key, "value": entry.value})
        logger.debug(f"\"{a.label}\" ({a.id}): {identifier}")

    asset_twas_updates = []
    asset_cs_updates = []

    for a in assets:
        twas_updates = []
        cs_updates = []

        if a.metadata:
            for entry in a.metadata:
                if entry.key == event_key:
                    logger.info(f"{a.label}: {entry.value}")
                    if "true" in entry.value or "false" in entry.value:
                        logger.info(f"Control update: {a.label}: {entry.value}")
                        cs_updates.append(entry.value)
                    else:
                        logger.info(f"TWAS update: {a.label}: {entry.value}")
                        twas_updates.append(entry.value)
                else:
                    if "*" in entry.key:
                        #logger.debug(f"Located * in metadata key: {entry.key} (assume regex)")
                        #assume key is a regular expression
                        if re.search(entry.key, event_key):
                            #logger.debug(f"Found match for event key: {event_key}")
                            logger.info(f"{event_key} matches {entry.key}")
                            logger.info(f"{a.label}: {entry.value}")
                            #twas_updates.append(entry.value)
                            if "true" in entry.value or "false" in entry.value:
                                logger.info(f"Control update: {a.label}: {entry.value}")
                                cs_updates.append(entry.value)
                            else:
                                logger.info(f"TWAS update: {a.label}: {entry.value}")
                                twas_updates.append(entry.value)

        if len(twas_updates) > 0:
            asset = Asset()
            asset.id = a.id
            asset.label = a.label
            asset_twas_updates.append({"asset": asset, "twas_updates": twas_updates})

        if len(cs_updates) > 0:
            asset = Asset()
            asset.id = a.id
            asset.label = a.label
            asset_cs_updates.append({"asset": asset, "cs_updates": cs_updates})

    #logger.debug(f"asset_twas_updates: {asset_twas_updates}")
    #logger.debug(f"asset_cs_updates: {asset_cs_updates}")

    if len(asset_twas_updates) == 0 and len(asset_cs_updates) == 0:
        raise Exception(f"No TWAS or Control updates configured for event key: {event_key}")

    if len(asset_twas_updates) > 0:
        for atu in asset_twas_updates:
            update_multiple_twas_for_asset(ssm_client, modelId, atu["asset"], atu["twas_updates"])

    if len(asset_cs_updates) > 0:
        for atu in asset_cs_updates:
            update_multiple_controls_for_asset(ssm_client, modelId, atu["asset"], atu["cs_updates"])    

#def set_tw_levels_for_asset(ssm_client: SSMClient, model_id, asset, event_name, event_status):
def update_multiple_twas_for_asset(ssm_client: SSMClient, model_id, asset, asset_twas_updates):
    # Get current TW sets for SSM asset
    tw_dict = get_tw_attr_sets_for_asset(ssm_client, model_id, asset)

    logger.debug(f"asset_twas_updates: {asset_twas_updates}")

    for asset_twas_update in asset_twas_updates:
        update_twas_for_asset(ssm_client, model_id, asset, tw_dict, asset_twas_update)

def update_twas_for_asset(ssm_client: SSMClient, model_id, asset, tw_dict, asset_twas_update):
    logger.debug(f"asset_twas_update: {asset_twas_update}")

    (tw_attr, level) = asset_twas_update.split("=")

    logger.debug(f"tw_attr: {tw_attr}")
    logger.debug(f"level: {level}")

    if tw_attr in tw_dict.keys():
        logger.info(f"Located \"{tw_attr}\" in TWAs list")

        twas = tw_dict[tw_attr]
        #logger.debug(f"twas: {twas}")

        twas_attribute = twas.attribute
        #logger.debug(f"twas_attribute: {twas_attribute}")
        attribute_label = twas_attribute.label
        #logger.debug(f"attribute_label: {attribute_label}")

        asserted_tw_level = twas.asserted_tw_level
        #logger.debug(f"asserted_tw_level: {asserted_tw_level}")
        asserted_tw_level_uri = asserted_tw_level.uri
        #logger.debug(f"asserted_tw_level_uri: {asserted_tw_level_uri}")
        asserted_tw_level_label = asserted_tw_level.label
        #logger.debug(f"asserted_tw_level_label: {asserted_tw_level_label}")
        logger.info(f"Current SSM tw level: {asserted_tw_level_label}")

        #logger.info(f"SIEA requests update to TW attribute \"{attribute_label}\" from {old_value} to {new_value}")

        #N.B. we now get the appropriate level not from UDE but according to the event
        #Map from UDE level (e.g. HIGH) to SSM equivalent (e.g. High)
        #ssm_tw_level = map_ude_tw_level(new_value)

        #Get TW level according to event name and status
        #ssm_tw_level = map_event_tw_level(event_name, event_status)

        #Get TW level from incoming level
        ssm_tw_level = level

        logger.info(f"New SSM tw level: {ssm_tw_level}")

        #Create full URI for the level
        new_tw_level_uri = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevel" + ssm_tw_level
        #TODO: check if URI is in the list of acceptable values?

        logger.debug(f"New TW value URI: {new_tw_level_uri}")

        ssm_client.update_single_twas(attribute_label, twas, new_tw_level_uri, asset.id, asset.label, None, model_id)
    else:
        raise Exception(f"Could not locate \"{tw_attr}\" in TWAs list")

def map_ude_tw_level(ude_tw_level):
    tw_levels_dict = {
        "VERYHIGH": "VeryHigh",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "VERYLOW": "VeryLow"
    }
    ssm_tw_level = tw_levels_dict[ude_tw_level]
    logger.debug(f"UDE level \"{ude_tw_level}\" maps to SSM level \"{ssm_tw_level}\"")
    return ssm_tw_level

def map_event_tw_level(event_name, event_status):
    tw_levels_dict = {
        "DoorOpen_FullLockDown": "VeryLow",
        "DoorClosed_PartialLockDown": "Medium",
        "ClearanceGiven_NoLockDown": "VeryHigh",
        "PhysicalTampering_PartialLockDown": "VeryLow",
        "Reset_Reset": "VeryHigh",
        "DataLeakDetected": "Low",
        "DataManipulationDetected": "VeryLow",
        "TamperingResolved": "VeryHigh",
        "Reset": "VeryHigh"
    }

    event_key = event_name
    if event_status:
        event_key += "_" + event_status
    logger.debug(f"event_key: {event_key}")

    #Ensure that event_key is a valid key
    if event_key not in tw_levels_dict.keys():
        raise Exception(f"No TW level defined for event: {event_key}")

    ssm_tw_level = tw_levels_dict[event_key]
    logger.info(f"Event \"{event_key}\" maps to SSM TW level \"{ssm_tw_level}\"")
    return ssm_tw_level

# Get dict of TWAs, indexed by TWA label
def get_tw_attr_sets_for_asset(ssm_client: SSMClient, model_id, asset):
    #logger.debug(f"asset: {asset}")

    # asset only contains basic details, so download current twas first
    logger.debug(f"Getting TWAs for asset: {asset.label} ({asset.id})...")
    tw_attr_sets = ssm_client.get_asset_twas(asset.id, model_id)

    logger.debug(f"Current TWAs levels:")
    tw_dict = {} #TWAs dict, referenced by label
    for tw_key, twas in tw_attr_sets.items():
        twas_attribute = twas.attribute
        #logger.debug(f"twas_attribute: {twas_attribute}")
        attribute_label = twas_attribute.label
        #logger.debug(f"attribute_label: {attribute_label}")
        asserted_tw_level = twas.asserted_tw_level
        #logger.debug(f"asserted_tw_level: {asserted_tw_level}")
        if asserted_tw_level is not None:
            asserted_tw_level_uri = asserted_tw_level.uri
            #logger.debug(f"asserted_tw_level_uri: {asserted_tw_level_uri}")
            asserted_tw_level_label = asserted_tw_level.label
            #logger.debug(f"asserted_tw_level_label: {asserted_tw_level_label}")
            logger.debug(f"\"{attribute_label}\" = \"{asserted_tw_level_label}\"")
        else:
            logger.debug(f"\"{attribute_label}\" = None")

        #Add to dict
        tw_dict[attribute_label] = twas

    return tw_dict

def apply_changes_made_to_as_is_model(ssm_client, modelId, changes_made_to_as_is_model, event_name=None, event_status=None):
    model_changes = []

    n_changes = len(changes_made_to_as_is_model)
    logger.info(f"{n_changes} changes to model")

    for change_made_to_as_is_model in changes_made_to_as_is_model:
        object_to_identify = change_made_to_as_is_model.object_to_identify
        object_name = object_to_identify.name
        changes = change_made_to_as_is_model.changes

        #Query SSM to locate asset with identified metadata
        assets = ssm_client.get_ssm_asset(modelId, 
            name=object_to_identify.name,
            type=object_to_identify.type,
            atid=object_to_identify.atid
        )

        n_assets = len(assets)
        logger.info(f"Located {n_assets} assets:");

        if n_assets > 0:
            asset = assets[0]
            for a in assets: 
                logger.info(f"\"{a.label}\" ({a.id})")
            if n_assets > 1:
                logger.warn("Located multiple assets with same metadata - will select first..")

            #Apply the changes to the asset in the SSM
            asset_changes = apply_changes(ssm_client, modelId, asset, object_to_identify, changes, event_name, event_status)
            model_changes.append(asset_changes)
        else:
            raise Exception(f"No SSM asset found for object_to_identify: {object_to_identify}")

    return model_changes

def apply_changes(ssm_client, modelId, asset, object_to_identify, changes, event_name=None, event_status=None):
    control_set_changes = []
    control_sets = dict()

    asset_name = asset.label
    logger.debug(f"object_to_identify: {object_to_identify}")
    logger.debug(f"apply_changes to asset: {asset_name}")

    for change in changes:
        ch_type = change.change_type
        attr = change.attribute_changed
        attr_type = change.attribute_type
        attr_old = change.attribute_old_value
        attr_new = change.attribute_new_value

        logger.info(f"'{asset_name}' change in {attr}: {attr_old} -> {attr_new}")

        if attr == "disab" or attr == "blocked":
            control_set_change = {}
            #logger.debug("attr == disab")
            #logger.debug(f"type: {object_to_identify.type}")

            if "ReadDataFlow" in object_to_identify.type:
                #logger.debug("ReadDataFlow")
                control_label = "DisableClientAccess"
            elif "WriteDataFlow" in object_to_identify.type:
                #logger.debug("WriteDataFlow")
                control_label = "DisableDataFlow"
            else:
                #logger.debug("other")
                #Get FP_DISABLEMENT_CONTROL from config/.env
                control_label = FP_DISABLEMENT_CONTROL

            if attr_new == "true":
                #logger.debug("attr_new == true")
                logger.info(f"('{asset_name}' disabled)")
                control_value = True
                (selected_control_set, control_set_change) = update_control_on_asset(ssm_client, modelId, asset, control_label, control_value)
            else:
                #logger.debug("attr_new == false")
                logger.info(f"('{asset_name}' enabled)")
                control_value = False
                (selected_control_set, control_set_change) = update_control_on_asset(ssm_client, modelId, asset, control_label, control_value)

            control_set_changes.append(control_set_change)
            control_sets[selected_control_set.uri] = selected_control_set
        elif attr == "isActive":
            control_set_change = {}
            #logger.debug("attr == isActive")

            control_label = "DisabledHost"

            if attr_new == "true":
                #logger.debug("attr_new == true")
                logger.info(f"('{asset_name}' is Active)")
                control_value = False
                (selected_control_set, control_set_change) = update_control_on_asset(ssm_client, modelId, asset, control_label, control_value)
            else:
                #logger.debug("attr_new == false")
                logger.info(f"('{asset_name}' is Not Active)")
                control_value = True
                (selected_control_set, control_set_change) = update_control_on_asset(ssm_client, modelId, asset, control_label, control_value)

            control_set_changes.append(control_set_change)
            control_sets[selected_control_set.uri] = selected_control_set
        elif attr == "trustworthy":
            logger.info("Setting trustworthiness value")
            #Set the TW level(s) for the asset in the SSM
            set_tw_level_for_asset(ssm_client, modelId, asset, event_name, event_status)
        else:
            raise Exception(f"Attribute not supported: {attr}")

    a = Asset()
    a.id = asset.id
    a.label = asset.label
    a.control_sets = control_sets

    asset_changes = {"asset": a, "control_sets": control_set_changes}
    #logger.debug(f"Asset changes: {asset_changes}")

    return asset_changes

def update_multiple_controls_for_asset(ssm_client: SSMClient, model_id, asset, asset_control_updates):
    # Get current control sets for SSM asset
    control_sets = get_control_sets_for_asset(ssm_client, model_id, asset)

    logger.debug(f"asset_control_updates: {asset_control_updates}")

    for asset_control_update in asset_control_updates:
        update_control_for_asset(ssm_client, model_id, asset, control_sets, asset_control_update)

# Get dict of Controls, indexed by control label
def get_control_sets_for_asset(ssm_client: SSMClient, model_id, asset):
    #logger.debug(f"asset: {asset}")

    # asset only contains basic details, so download current control sets first
    logger.debug(f"Getting control sets for asset {asset.id}...")
    control_sets = ssm_client.get_asset_control_sets(asset.id, model_id)
    #logger.debug(f"control_sets: {control_sets}");

    logger.debug(f"Current controls:")
    controls_dict = {} # Controls dict, referenced by label

    for cs_key, cs in control_sets.items():
        logger.debug(f"\"{cs.label}\" = \"{cs.proposed}\"")
        #Add to dict
        controls_dict[cs.label] = cs

    return controls_dict

def update_control_for_asset(ssm_client: SSMClient, model_id, asset, cs_dict, asset_cs_update):
    logger.debug(f"asset_cs_update: {asset_cs_update}")

    (control, new_value) = asset_cs_update.split("=")

    logger.debug(f"control: {control}")
    logger.debug(f"new_value: {new_value}")

    if control in cs_dict.keys():
        logger.info(f"Located \"{control}\" in controls list")

        cs = cs_dict[control]
        #logger.debug(f"cs: {cs}")

        logger.info(f"Current SSM control value: {cs.proposed}")

        #logger.info(f"SIEA requests update to TW attribute \"{attribute_label}\" from {old_value} to {new_value}")

        logger.info(f"New SSM control value: {new_value}")

        cs.proposed = new_value

        #Update the control set via SSM
        logger.info(f"Calling SSM update control set...");
        ssm_client.update_control_for_asset(model_id, cs.asset_id, cs)
        logger.info(f"SSM updated control set OK");
    else:
        raise Exception(f"Could not locate \"{control}\" in controls list")

def update_control_on_asset(ssm_client, modelId, asset, control_label, control_value):
    logger.info(f"Updating control '{control_label}' to {control_value} on asset '{asset.label}'")
    #logger.debug(f"asset: {asset}")
    
    selected_control_set = None
    
    # asset only contains basic details, so download current control sets first
    logger.debug(f"Getting control sets for asset {asset.id}...")
    control_sets = ssm_client.get_asset_control_sets(asset.id, modelId)

    for curi, control_set in control_sets.items():
        #logger.debug(f"control_set: {control_set}")
        if control_set.label == control_label:
            selected_control_set = control_set
            break

    if selected_control_set is None:
        raise Exception(f"Could not locate control set '{control_label}' for asset '{asset.label}'")

    #logger.debug(f"Current control set: {selected_control_set}");
    #TODO: Ideally create simpler control set object, just containing the essential fields for the SSM request

    #Save the current proposed value
    old_value = selected_control_set.proposed

    #Update the control set object
    selected_control_set.proposed = control_value
    new_value = control_value
    #logger.debug(f"Updated control set: {selected_control_set}");

    #Update the control set via SSM
    logger.info(f"Calling SSM update control set...");
    ssm_client.update_control_for_asset(modelId, selected_control_set.asset_id, selected_control_set)
    logger.info(f"SSM updated control set OK");

    #Record the details of the control set change (allows future rollback)
    control_set_change = {"control": control_label, "old_value": old_value, "new_value": new_value}

    return (selected_control_set, control_set_change)

def revert_changes_made_to_ssm_model(ssm_client, modelId, ssm_model_changes):
    logger.info(f"Reverting changes to SSM model...")
    #logger.debug(f"ssm_model_changes {ssm_model_changes}")
    for change_set in ssm_model_changes:
        asset = change_set["asset"]
        logger.debug(f"asset: {asset.label}")
        control_set_changes = change_set["control_sets"]
        logger.debug(f"control_set_changes: {control_set_changes}")
        for control_set_change in control_set_changes:
            control = control_set_change["control"]
            reverted_value = control_set_change["old_value"]
            update_control_on_asset(ssm_client, modelId, asset, control, reverted_value)


# Get object_to_identify from identifiers in risk object
def get_object_to_identify_from_risk(risk):
    #logger.debug(f"risk: {risk}")
    asset = risk["asset"]
    #logger.debug(f"asset: {asset}")
    name = asset["label"]
    #logger.debug(f"name: {name}")
    object_identifiers = asset["identifiers"]
    #logger.debug(f"object_identifiers: {object_identifiers}")

    object_to_identify = {}

    if not object_identifiers:
        object_to_identify = {"name": name, "type": "", "atid": ""}
        #logger.debug(f"No metadata defined for asset: \"{name}\"")
        #logger.debug(f"setting to: {object_to_identify}")
    else:
        object_to_identify = get_object_identifiers_map(object_identifiers)

        obj_keys = object_to_identify.keys()

        if "name" not in obj_keys:
            object_to_identify["name"] = name
        if "atid" not in obj_keys:
            object_to_identify["atid"] = ""
        if "type" not in obj_keys:
            object_to_identify["type"] = ""

    #logger.debug(f"object_to_identify: {object_to_identify}")
    return object_to_identify

# Get object identifiers as key/value pairs
# N.B. In Fogprotect we assume unique identifiers, e.g. name, type, atid
def get_object_identifiers_map(object_identifiers):
    identifiers = {}

    for identifier in object_identifiers:
        identifiers[identifier['key']] = identifier['value']

    #logger.debug(f"identifiers: {identifiers}")
    return identifiers

def format_risk_calc_response(risk_results, siea_task_id):
    top_risks = risk_results["risks"]
    risk_vector = risk_results["risk_vector"]
    overall_risk_level = risk_results["overall_risk_level"]

    logger.debug(f"top_risks: {top_risks}")
    logger.info(f"risk_vector: {risk_vector}")
    logger.info(f"overall_risk_level: {overall_risk_level}")

    risks = []

    #Extract risk info from top_risks (misbehaviours) and populate risks array
    logger.debug("Extracting risks info from top risks...")
    for top_risk in top_risks:
        risk = {}

        object_to_identify = get_object_to_identify_from_risk(top_risk)
        #logger.debug(f"object_to_identify: {object_to_identify}")

        risk["object_to_identify"] = object_to_identify
        risk["risk_name"] = top_risk["label"]
        risk["risk_description"] = top_risk["description"]
        risk["risk_impact"] = top_risk["impact"]
        risk["risk_likelihood"] = top_risk["likelihood"]
        risk["risk_level"] = top_risk["risk"]
        risks.append(risk)

    # build ResultOfRiskCalculation response
    logger.debug("Creating ResultOfRiskCalculation response to UDE..")
    logger.debug(f"ACCEPTABLE_RISK_LEVEL = {ACCEPTABLE_RISK_LEVEL}")

    result = {"notification_type": "ResultOfRiskCalculation", "siea_task_id": siea_task_id}
    result["risks"] = risks
    result["risk_vector"] = risk_vector
    result["overall_risk_level"] = overall_risk_level
    result["acceptable_risk_level"] = ACCEPTABLE_RISK_LEVEL

    logger.debug(f"RESULT: {result}")

    return ResultOfRiskCalculation(**result)

def format_risk_calc_response_rec(rec_results, siea_task_id):
    """ format risk response including recommendatins """

    #top_risks = risk_results["risks"]
    top_risks = rec_results.current.state.consequences

    #risk_vector = risk_results["risk_vector"]
    risk_vector = rec_results.current.state.risk.components

    #overall_risk_level = risk_results["overall_risk_level"]
    overall_risk_level = rec_results.current.state.risk.overall

    logger.debug(f"top_risks: {top_risks}")
    logger.info(f"risk_vector: {risk_vector}")
    logger.info(f"overall_risk_level: {overall_risk_level}")

    risks = []

    #Extract risk info from top_risks (misbehaviours) and populate risks array
    logger.debug("Extracting risks info from top risks...")
    for top_risk in top_risks:
        risk = {}

        #object_to_identify = get_object_to_identify_from_risk(top_risk)
        #logger.debug(f"object_to_identify: {object_to_identify}")

        risk["object_to_identify"] = {'name': top_risk.asset.label, 'atid': top_risk.asset.identifier, 'type': top_risk.asset.type}
        risk["risk_name"] = top_risk.label
        risk["risk_description"] = top_risk.description
        risk["risk_impact"] = top_risk.impact
        risk["risk_likelihood"] = top_risk.likelihood
        risk["risk_level"] = top_risk.risk
        risks.append(risk)

    # build ResultOfRiskCalculation response
    logger.debug("Creating ResultOfRiskCalculation response to UDE..")
    logger.debug(f"ACCEPTABLE_RISK_LEVEL = {ACCEPTABLE_RISK_LEVEL}")

    result = {"notification_type": "ResultOfRiskCalculation", "siea_task_id": siea_task_id}
    result["risks"] = risks
    result["risk_vector"] = risk_vector.dict()
    result["overall_risk_level"] = overall_risk_level
    result["acceptable_risk_level"] = ACCEPTABLE_RISK_LEVEL

    logger.debug(f"RESULT: {result}")

    return ResultOfRiskCalculation(**result)
