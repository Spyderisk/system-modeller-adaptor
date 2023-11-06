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
import traceback

from app.core.config import RISK_CALC_MODE
from app.core.config import FP_ENABLE_RECOMMENDATIONS
from .fp_helper_methods import apply_changes_made_to_as_is_model, get_object_to_identify_from_risk, format_risk_calc_response, update_multiple_twas_or_controls_for_assets, get_assets_for_event
from .fp_helper_methods import format_risk_calc_response_rec
from app.ssm.ssm_client import SSMClient
from ssm_api_client import Asset
from app.models.session import SessionLock, SessionLockEnum
from app.crud.store import update_status, get_vjob
from app.crud.store import release_session_lock, get_session

from app.clients.ude_client import post_notification
from app.models.fogprotect.adaptation_coordinator.notification_models import ResultOfRiskCalculation
from app.models.fogprotect.adaptation_coordinator.notification_models import ObjectToIdentify as ObjectToIdentifyOut
from app.models.fogprotect.adaptation_coordinator.notification_models import Risk

from app.models.risk import RiskVector
from fastapi.encoders import jsonable_encoder

from app.models.fogprotect.event_notification import EventNotification as EventNotificationIn
from app.models.fogprotect.event_notification import Vulnerability
from app.models.fogprotect.event_notification import ObjectToIdentify as ObjectToIdentifyIn

# recommendations imports
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.ssm.cyberkit4sme.shortest_path import ShortestPathDataset, ThreatTree
from app.ssm.cyberkit4sme.shortest_path_mitigation import ShortestPathMitigation

from fastapi.logger import logger


async def bg_evaluate_event_risks(event: EventNotificationIn, modelId: str,
        vjid: str, db_conn, ssm_client: SSMClient, rec_mode:bool=False, verbose=True):

    if FP_ENABLE_RECOMMENDATIONS:
        rec_mode = True
    else:
        rec_mode = False

    logger.info(f"Serving background task for evaluate event risks with POST, recommendation mode: {rec_mode}")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task: extract request data and evaluate model risk

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

        logger.info(f"source: {vuln.source}")
        logger.info(f"event_name: {event_name}")
        logger.info(f"reason: {vuln.reason}")
        logger.info(f"timestamp: {event_timestamp}")

        if event_name == "Reset":
            logger.info("RESET EVENT")

            # Apply the changes made to the as-is model
            apply_changes_made_to_as_is_model(ssm_client, modelId, changes_made_to_as_is_model_list, event_name, event_status)
        else:
            # Get assets with TWAS related to this event
            assets = get_assets_for_event(ssm_client, modelId, event)

            if vuln.source == "wazuh":
                # Define event key, based on event name and filename field in vulnerability
                logger.info(f"filename: {vuln.filename}")
                event_key = event_name + ":" + vuln.filename
            elif vuln.source == "fybrik" or vuln.source == "adaptationCoordinator" or vuln.source == "administrator":
                logger.info(f"actor: {vuln.actor}")
                logger.info(f"method: {vuln.method}")
                logger.info(f"sub: {vuln.sub}")
                logger.info(f"user: {vuln.user}")
                logger.info(f"role: {vuln.role}")
                logger.info(f"org: {vuln.org}")
                logger.info(f"endpoint: {vuln.endpoint}")
                logger.info(f"attempts: {vuln.attempts}")
                logger.info(f"windowSize: {vuln.windowSize}")
                logger.info(f"threshold: {vuln.threshold}")

                """
                if "Multiple unauthorized read access attempts for user" in vuln.reason:
                    reason_id = "mult_read_attempts"
                elif "SLA_for_user_exceeded " in vuln.reason:
                    reason_id = "SLA_for_user_exceeded"
                else:
                    reason_id = "unknown"
                """

                if event_name == "EndPointBlockedReport" or event_name == "EndPointUnBlockedReport":
                    reason_id = "mult_" + vuln.actor + "_" + vuln.method
                elif event_name == "EndPointGrantedReport":
                    reason_id = "SLA_" + vuln.actor + "_" + vuln.method
                else:
                    reason_id = "unknown"

                logger.info(f"reason_id: {reason_id}")
                event_key = event_name + ":" + reason_id
                logger.info(f"event_key: {event_key}")
            else:
                raise Exception(f"Unsupported source: {vuln.source}")

            # Update TWAS or Controls on one or more assets, according to the asset metadata for specified event key
            update_multiple_twas_or_controls_for_assets(ssm_client, modelId, assets, event_key)

        logger.info("Calculating model risk")

        if rec_mode:
            logger.debug("getting recommendations")
            #risk_results = ssm_client.calculate_runtime_risk_vector_full(modelId, RISK_CALC_MODE)
            #logger.debug(f"risk_results: {risk_results}")
            #logger.debug(f"risk_results type: {type(risk_results)}")
            #logger.debug(f"risk_results: {json.dumps(risk_results, indent=2)}")
            shortest_path = ShortestPathMitigation(ssm_client, modelId, RISK_CALC_MODE)
            shortest_path.prepare_datasets()
            shortest_path.algorithm_shortest_path()
            vul_recommendation = shortest_path.get_recommendations_obj()
            json_response = jsonable_encoder(vul_recommendation)
            logger.debug(f"RECOMMENDATIONS: {vul_recommendation}")
            logger.debug(f"RECOMMENDATIONS: {type(vul_recommendation)}")
            logger.debug(f"RECOMMENDATIONS: {json.dumps(json_response, indent=2)}")
            risk_calc_response = format_risk_calc_response_rec(vul_recommendation, siea_task_id)
            risk_calc_response.recommendations = vul_recommendation.recommendations
            logger.debug(f"ResultOfRickCalculation: {risk_calc_response}")
        else:
            # Calculate the risks of the current state
            risk_results = ssm_client.calculate_runtime_risk_vector_full(modelId, RISK_CALC_MODE)
            logger.debug(f"risk_results: {risk_results}")

            # Format risk results for UDE response
            risk_calc_response = format_risk_calc_response(risk_results, siea_task_id)

        if event_name == "Reset":
            #Do not post risk results to UDE component, if handling a reset event
            logger.info("RESET COMPLETE")
        else:
            logger.info("background task ready to post to UDE")
            payload = jsonable_encoder(risk_calc_response)
            post_notification(payload)
            logger.info("background task finished posting to UDE")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background notification task has finished")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        traceback.print_exception(type(e), e, e.__traceback__)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.debug(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return


async def bg_evaluate_event_risks_simulated(event: EventNotificationIn, modelId: str,
        vjid: str, db_conn, ssm_client: SSMClient, verbose=True):

    logger.info("Serving dummy background task for evaluate event risks with POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task, evaluate model risk
        await asyncio.sleep(2)

        vulnerabilities = event.vulnerabilities #array of vulnerabilities

        vuln = vulnerabilities[0] #assume ony one for now
        logger.debug(f"vulnerability: {vuln}")

        changes_made_to_as_is_model_list = vuln.changes_made_to_as_is_model
        changes_made_to_as_is_model = changes_made_to_as_is_model_list[0] #assume ony one for now
        object_to_identify = changes_made_to_as_is_model.object_to_identify
        changes = changes_made_to_as_is_model.changes
        logger.debug(f"object_to_identify: {object_to_identify}")
        logger.debug(f"changes: {changes}")

        event_name = event.event_name
        event_timestamp = event.timestamp

        logger.info(f"event_name: {event_name}")
        logger.info(f"timestamp: {event_timestamp}")

        # build ResultOfRiskCalculation
        result = {"notification_type": "ResultOfRiskCalculation"}
        rv = RiskVector()
        rv.randomise()

        overall_risk_level = "Very High"

        #UC2
        if event_name == "DoorOpen" and event_status == "FullLockDown":
            logger.info("Door open / full lockdown event") #TW HIGH -> LOW
            rv.very_high = 5
            rv.high = 10
            overall_risk_level = "Very High"
        elif event_name == "DoorOpen":
            logger.info(f"Door open / {event_status} event") #unhandled event
            logger.warn(f"Unhandled event_status: {event_status}")
            overall_risk_level = "Very High"
        elif event_name == "DoorClosed" and event_status == "PartialLockDown":
            logger.info("Door closed / partial lockdown event") #TW LOW -> MEDIUM
            rv.very_high = 0
            rv.high = 0
            rv.medium = 0
            overall_risk_level = "Low"
        elif event_name == "DoorClosed":
            logger.info(f"Door closed / {event_status} event") #unhandled event
            logger.warn(f"Unhandled event_status: {event_status}")
            rv.high = 0
            rv.medium = 0
            overall_risk_level = "Low"
        elif event_name == "ClearanceGiven" and event_status == "NoLockDown":
            logger.info("Clearance given / no lockdown event") #TW MEDIUM -> HIGH?
            rv.very_high = 0
            rv.high = 0
            overall_risk_level = "Medium"
        elif event_name == "ClearanceGiven":
            logger.info("Clearance given / {event_status} event") #unhandled event
            logger.warn(f"Unhandled event_status: {event_status}")
            rv.very_high = 0
            rv.high = 0
            overall_risk_level = "Medium"
        #UC1
        elif event_name == "PhysicalTampering" and event_status == "PartialLockDown":
            logger.info("Physical tampering / partial lockdown event") #TW HIGH -> LOW
            rv.very_high = 5
            rv.high = 10
            overall_risk_level = "Very High"
        elif event_name == "PhysicalTampering":
            logger.info(f"Physical tampering / {event_status} event") #unhandled event
            logger.warn(f"Unhandled event_status: {event_status}")
            rv.very_high = 5
            rv.high = 10
            overall_risk_level = "Very High"
        else:
            logger.warn(f"Unhandled event_name / event_status: {event_name} / {event_status}")

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
        result["acceptable_risk_level"] = "Medium"

        logger.info(f"RESULT: {result}")

        logger.info("background task ready to post to UDE")
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
