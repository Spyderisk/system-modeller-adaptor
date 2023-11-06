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

from app.core.config import ACCEPTABLE_RISK_LEVEL, RISK_CALC_MODE
from app.ssm.ssm_client import SSMClient
from app.models.session import SessionLock, SessionLockEnum
from app.crud.store import update_status, get_vjob
from app.crud.store import release_session_lock, get_session

from .fp_helper_methods import apply_changes_made_to_as_is_model, format_risk_calc_response
from app.clients.ude_client import post_notification
from app.models.fogprotect.adaptation_coordinator.notification_models import ResultOfRiskCalculation
from app.models.fogprotect.adaptation import (AdaptationProposalsRequest, AdaptationExecutedRequest, AdaptationResponse)
from app.models.fogprotect.adaptation_coordinator.notification_models import EvaluationOfAdaptation
from app.models.fogprotect.adaptation_coordinator.notification_models import ObjectToIdentify as ObjectToIdentifyOut
from app.models.fogprotect.adaptation_coordinator.notification_models import Risk, AsIsRisk, RiskLevel

from app.models.risk import RiskVector
from fastapi.encoders import jsonable_encoder

from app.models.fogprotect.event_notification import EventNotification as EventNotificationIn
from app.models.fogprotect.event_notification import Vulnerability
from app.models.fogprotect.event_notification import ObjectToIdentify as ObjectToIdentifyIn

from fastapi.logger import logger

async def bg_adaptation_executed(adaptation: AdaptationExecutedRequest, modelId: str,
        vjid: str, db_conn, ssm_client: SSMClient, verbose=True):

    logger.info("Serving background task for adaptation executed with POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task: extract request data and evaluate model risk
        #logger.debug(f"adaptation executed request: {adaptation}")

        siea_task_id = adaptation.siea_task_id
        logger.info(f"siea_task_id: {siea_task_id}")

        changes_made_to_as_is_model = adaptation.as_is.changes_made_to_as_is_model
        logger.info(f"changes_made_to_as_is_model: {changes_made_to_as_is_model}")

        # Apply the changes made to the as-is model
        apply_changes_made_to_as_is_model(ssm_client, modelId, changes_made_to_as_is_model)

        logger.info("Calculating model risk")

        # Calculate the risks of the current state
        risk_results = ssm_client.calculate_runtime_risk_vector_full(modelId, RISK_CALC_MODE)
        logger.debug(f"risk_results: {risk_results}")

        # Format risk results for UDE response
        risk_calc_response = format_risk_calc_response(risk_results, siea_task_id)

        logger.info("background task ready to post to UDE")
        payload = jsonable_encoder(risk_calc_response)
        post_notification(payload)
        logger.info("background task finished posting to UDE")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background notification task has finished")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.debug(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return


async def bg_adaptation_executed_simulated(adaptation: AdaptationExecutedRequest, modelId: str,
        vjid: str, db_conn, ssm_client: SSMClient, verbose=True):

    logger.info("Serving dummy background task for adaptation executed with POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task, evaluate model risk
        await asyncio.sleep(2)

        #logger.debug(f"adaptation: {adaptation}")

        as_is_model = adaptation.as_is.as_is_model
        #logger.debug(f"as_is_model: {as_is_model}")

        tosca_nodes_root = as_is_model.tosca_nodes_root
        #logger.debug(f"tosca_nodes_root: {tosca_nodes_root}")

        tw_values = {"VERYHIGH" : 4, "HIGH" : 3, "MEDIUM" : 2, "LOW" : 1, "VERYLOW" : 0}
        overall_tw = tw_values["VERYHIGH"]

        for tosca_node in tosca_nodes_root:
            #logger.debug(f"{tosca_node.name} {tosca_node.atid} {tosca_node.type}")
            if tosca_node.type == "PrivateSpace":
                tw = tosca_node.trustworthy
                logger.info(f"{tosca_node.name} {tosca_node.atid} {tosca_node.type} TW = {tw}")
                #logger.debug(f"tw type: {type(tw)}")
                if tw == 'False':
                    logger.warn(f"trustworthy value should be string: {tw}")
                    tw = "VERYLOW"
                elif tw == 'True':
                    logger.warn(f"trustworthy value should be string: {tw}")
                    tw = "VERYHIGH"
                if tw_values[tw] < overall_tw:
                    overall_tw = tw_values[tw]

        logger.info(f"Overall trustworthy = {overall_tw}")
        trustworthy = (overall_tw >= tw_values["MEDIUM"])
        logger.info(f"Model trustworthy = {trustworthy}")

        changes_made_to_as_is_model = adaptation.as_is.changes_made_to_as_is_model
        logger.debug(f"changes_made_to_as_is_model: {changes_made_to_as_is_model}")

        n_changes = len(changes_made_to_as_is_model)
        logger.info(f"{n_changes} changes to model")

        change_in_risk = 0 #approx indication of how overall risk has changed

        for change_made_to_as_is_model in changes_made_to_as_is_model:
            object_to_identify = change_made_to_as_is_model.object_to_identify
            object_name = object_to_identify.name
            changes = change_made_to_as_is_model.changes

            for change in changes:
                ch_type = change.change_type
                attr = change.attribute_changed
                attr_type = change.attribute_type
                attr_old = change.attribute_old_value
                attr_new = change.attribute_new_value

                logger.info(f"'{object_name}' change in {attr}: {attr_old} -> {attr_new}")
                if attr == "trustworthy":
                    if attr_new == "HIGH" or attr_new == "high":
                        logger.info(f"('{object_name} trustworthiness increased - decreasing risk)")
                        change_in_risk -= 1
                    else:
                        logger.info(f"('{object_name} trustworthiness reduced - increasing risk)")
                        change_in_risk += 1
                elif attr == "disab":
                    disabled = False

                    if attr_new == "true":
                        disabled = True
                    else:
                        disabled = False

                    if trustworthy and disabled:
                        logger.info(f"('{object_name} disabled and model trustworthy - decreasing risk)")
                        change_in_risk -= 1
                    elif trustworthy and not disabled:
                        logger.info(f"('{object_name} enabled and model trustworthy - no change in risk)")
                    elif not trustworthy and disabled:
                        logger.info(f"('{object_name} disabled and model not trustworthy - decreasing risk)")
                        change_in_risk -= 1
                    elif not trustworthy and not disabled:
                        logger.info(f"('{object_name} enabled and model not trustworthy - increasing risk)")
                        change_in_risk += 1

        # build ResultOfRiskCalculation
        result = {"notification_type": "ResultOfRiskCalculation"}
        rv = RiskVector()
        rv.randomise()

        overall_risk_level = "Very High"

        if change_in_risk < 0:
            logger.info("Overall risk has reduced")
            rv.very_high = 0
            rv.high = 0
            rv.medium = 0
            overall_risk_level = "Low"
        elif change_in_risk > 0:
            logger.info("Overall risk has increased")
            rv.very_high = 5
            rv.high = 10
            overall_risk_level = "Very High"
        else:
            logger.info("Overall risk has not changed")
            rv.very_high = 0
            rv.high = 10
            overall_risk_level = "Medium"

        result["risk_vector"] = rv

        risk = {}
        risk["object_to_identify"] = {"name": "mock object name",
                "type": "mock object type", "atid": "mock id"}
        risk["risk_description"] = "risk description"
        risk["risk_impact"] = rv.random_level()
        risk["risk_name"] = "risk name"
        risk["risk_likelihood"] = rv.random_level()
        risk["risk_level"] = rv.random_level()
        result["risks"] = [risk]

        result["overall_risk_level"] = overall_risk_level
        result["acceptable_risk_level"] = ACCEPTABLE_RISK_LEVEL

        logger.debug(f"RESULT: {result}")

        logger.info("background task ready to post to UDE")
        #payload = jsonable_encoder(EvaluationOfAdaptation(**result))
        payload = jsonable_encoder(ResultOfRiskCalculation(**result))
        post_notification(payload)
        logger.info("background task finished posting to UDE")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background notification task has finised")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return
