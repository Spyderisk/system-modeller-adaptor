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
##      Created By :            Panos Melas
##      Created Date :          2021-02-23
##      Created for Project :   FogProtect
##
##///////////////////////////////////////////////////////////////////////

import os
import asyncio
import aiohttp
import json
import datetime
import time
from bson.objectid import ObjectId

from fastapi import HTTPException

from app.ssm.ssm_client import SSMClient
from ssm_api_client import Asset
from app.models.session import SessionLock, SessionLockEnum
from app.crud.store import update_status, get_vjob
from app.crud.store import release_session_lock, get_session

from .fp_helper_methods import update_multiple_twas_or_controls_for_assets, get_assets_for_event
from app.clients.ude_client import post_notification
from app.models.fogprotect.adaptation_coordinator.notification_models import ImmediateAction
from app.models.fogprotect.event_notification import EventNotification

from fastapi.encoders import jsonable_encoder

from fastapi.logger import logger


async def bg_notify_immediate_action_event(event: EventNotification, modelId: str, vjid: str, db_conn, ssm_client: SSMClient):

    logger.info("Serving immediate action task with notification POST")

    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        changes_made_to_as_is_model_list = event.changes_made_to_as_is_model
        changes_made_to_as_is_model = changes_made_to_as_is_model_list[0] #assume ony one for now
        logger.debug(f"changes_made_to_as_is_model: {changes_made_to_as_is_model}")
        object_to_identify = changes_made_to_as_is_model.object_to_identify
        logger.debug(f"object_to_identify: {object_to_identify}")

        vulnerabilities = event.vulnerabilities #array of vulnerabilities

        #vuln = vulnerabilities[0] #assume ony one for now
        vuln = vulnerabilities #this has been changed to a single object
        logger.debug(f"vulnerability: {vuln}")

        siea_task_id = event.siea_task_id
        logger.info(f"siea_task_id: {siea_task_id}")

        event_name = event.event_name
        event_timestamp = event.timestamp

        logger.info(f"event_name: {event_name}")
        logger.info(f"filename: {vuln.filename}")
        logger.info(f"timestamp: {event_timestamp}")

        #First, determine the immediate event info and pass on
        #immediate action request to UDE/WP5
        response_event = {"notification_type": "ImmediateAction", "siea_task_id": siea_task_id}

        for vul in event.vulnerabilities:
            if event_name:
               response_event["event_name"] = event_name
               break

        immediate_action = ImmediateAction(**response_event)
        payload = jsonable_encoder(immediate_action)
        logger.info("Sending immediate action notification to Adaptation Coordinator...")
        post_notification(payload)
        logger.info("Immediate action notification sent successfully")

        # Get assets with TWAS related to this event
        assets = get_assets_for_event(ssm_client, modelId, event)

        # Define event key, based on event name and filename field in vulnerability
        event_key = event_name + ":" + vuln.filename

        # Update TWAS or Controls on one or more assets, according to the asset metadata for specified event key
        update_multiple_twas_or_controls_for_assets(ssm_client, modelId, assets, event_key)

        # update job status
        await update_status(db_conn, vjid, "FINISHED")

        logger.info("Background immediate action task has finished OK")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.debug(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return

