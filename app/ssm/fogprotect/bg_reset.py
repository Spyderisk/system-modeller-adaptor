##///////////////////////////////////////////////////////////////////////
##
## (c) University of Southampton IT Innovation Centre, 2022
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
##      Created Date :          2022-09-12
##      Created for Project :   FogProtect
##
##///////////////////////////////////////////////////////////////////////

import os
import asyncio
import aiohttp
import json
import datetime
import time

from app.core.config import FP_USE_CASE
from .fp_helper_methods import update_multiple_twas_or_controls_for_assets, apply_changes_made_to_as_is_model, get_assets_for_event
from app.ssm.ssm_client import SSMClient
from ssm_api_client import Asset
from app.models.session import SessionLock, SessionLockEnum
from app.crud.store import update_status, get_vjob
from app.crud.store import release_session_lock, get_session
from app.clients.ude_client import post_notification
from fastapi.encoders import jsonable_encoder
from app.models.fogprotect.event_notification import Reset
from app.models.fogprotect.adaptation import ResetControlsRequest
from fastapi.logger import logger


async def bg_reset(reset: Reset, modelId: str,
        vjid: str, db_conn, ssm_client: SSMClient, verbose=True):

    logger.info("Serving background reset with POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        event_name = "Reset"

        logger.info(f"Reset for {FP_USE_CASE}")

        if FP_USE_CASE == "UC1":
            vuln_filename = "1654557758-raw.mp4"
        elif FP_USE_CASE == "UC2":
            vuln_filename = "app_config.py"
        elif FP_USE_CASE == "UC3":
            vuln_filename = "all"
        else:
            raise Exception(f"Use case not supported: {FP_USE_CASE}")

        # Get assets with TWAS related to this event
        assets = get_assets_for_event(ssm_client, modelId, None)

        # Define event key, based on event name and filename field in vulnerability
        event_key = event_name + ":" + vuln_filename

        # Update TWAS or Controls on one or more assets, according to the asset metadata for specified event key
        update_multiple_twas_or_controls_for_assets(ssm_client, modelId, assets, event_key)

        # Reset model controls
        reset_controls(ssm_client, modelId)

        #Do not post risk results to UDE component, if handling a reset event
        logger.info("RESET COMPLETE")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background reset task has finished")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.debug(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return

def reset_controls(ssm_client, modelId):
    logger.debug(f"Called reset_controls for {FP_USE_CASE}")

    if FP_USE_CASE == "UC1":
        reset_controls_json = get_reset_controls_json_uc1(ssm_client, modelId)
    elif FP_USE_CASE == "UC2":
        reset_controls_json = get_reset_controls_json_uc2(ssm_client, modelId)
    elif FP_USE_CASE == "UC3":
        reset_controls_json = get_reset_controls_json_uc3(ssm_client, modelId)
    else:
        raise Exception(f"Use case not supported: {FP_USE_CASE}")

    logger.debug(f"reset_controls_json: {reset_controls_json}")

    reset_controls = ResetControlsRequest.parse_obj(reset_controls_json)
    #logger.debug(f"reset_controls: {reset_controls}")

    changes = reset_controls.changes_made_to_as_is_model
    logger.debug(f"changes: {changes}")

    # Apply the changes
    apply_changes_made_to_as_is_model(ssm_client, modelId, changes)

    return

def get_reset_controls_json_uc1(ssm_client, modelId):
    #UC1
    reset_controls_json = {
        "ChangesMadeToAsIsModel": [
			{
				"ObjectToIdentify": {
					"name": "Data Flow (Camera Data Store on ubitnvidia.ubiwhere.lan - Local Authority Access Proxy)",
					"type": "fogprotect.adaptation.ComputingContinuumModel.DataFlow",
					"atid": "//@tosca_nodes_root.10"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "disab",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			},
			{
				"ObjectToIdentify": {
					"name": "Data Flow (Camera Data Store on ubitfognvidia.ubiwhere.lan - Local Authority Access Proxy)",
					"type": "fogprotect.adaptation.ComputingContinuumModel.DataFlow",
					"atid": "//@tosca_nodes_root.59"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "disab",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			}
		]
    }

    return reset_controls_json

def get_reset_controls_json_uc2(ssm_client, modelId):
    # UC2
    reset_controls_json = {
        "ChangesMadeToAsIsModel": [
			{
				"ObjectToIdentify": {
					"name": "WriteToNormalDatabase",
					"type": "fogprotect.adaptation.ComputingContinuumModel.WriteDataFlow",
					"atid": "//@tosca_nodes_root.46"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "disab",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			},
			{
				"ObjectToIdentify": {
					"name": "WriteToQuarantineDatabase",
					"type": "fogprotect.adaptation.ComputingContinuumModel.WriteDataFlow",
					"atid": "//@tosca_nodes_root.53"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "disab",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "false",
						"AttributeNewValue": "true"
					}
				]
			},
			{
				"ObjectToIdentify": {
					"name": "ReadDataFlow (User-NormalDB)",
					"type": "fogprotect.adaptation.ComputingContinuumModel.ReadDataFlow",
					"atid": "//@tosca_nodes_root.60"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "disab",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			},
			{
				"ObjectToIdentify": {
					"name": "ReadDataFlow (Admin-NormalDB)",
					"type": "fogprotect.adaptation.ComputingContinuumModel.ReadDataFlow",
					"atid": "//@tosca_nodes_root.61"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "disab",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			},
			{
				"ObjectToIdentify": {
					"name": "Robot Operation",
					"type": "fogprotect.adaptation.ComputingContinuumModel.SoftwareComponent",
					"atid": "//@tosca_nodes_root.63"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "isActive",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "false",
						"AttributeNewValue": "true"
					}
				]
			}
		]
    }

    return reset_controls_json

def get_reset_controls_json_uc3(ssm_client, modelId):
    # UC3
    reset_controls_json = {
        "ChangesMadeToAsIsModel": [
			{
				"ObjectToIdentify": {
					"name": "atc-vbu1",
					"type": "fogprotect.adaptation.ComputingContinuumModel.DataProcessor",
					"atid": "//@tosca_nodes_root.55"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "blocked",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			},
			{
				"ObjectToIdentify": {
					"name": "ATC",
					"type": "fogprotect.adaptation.ComputingContinuumModel.Group",
					"atid": "//@tosca_nodes_root.26"
				},
				"Changes": [
					{
						"ChangeType": "CHANGE",
						"AttributeChanged": "blocked",
						"AttributeType": "EBoolean",
						"AttributeOldValue": "true",
						"AttributeNewValue": "false"
					}
				]
			}
		]
    }

    return reset_controls_json
