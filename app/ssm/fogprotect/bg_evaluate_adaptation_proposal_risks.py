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

from .fp_helper_methods import apply_changes_made_to_as_is_model, revert_changes_made_to_ssm_model
from app.clients.ude_client import post_notification
from app.models.fogprotect.adaptation_coordinator.notification_models import EvaluationOfAdaptationProposals
from app.models.fogprotect.adaptation import (AdaptationProposalsRequest,
        AdaptationExecutedRequest, AdaptationResponse)

from app.models.risk import RiskVector
from fastapi.encoders import jsonable_encoder
from fastapi.logger import logger


async def bg_evaluate_adaptation_proposal_risks(proposals: AdaptationProposalsRequest,
        modelId: str, vjid: str, db_conn, ssm_client: SSMClient, verbose=True):

    logger.info("Serving background task for evaluate adaptation proposal risks with POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        #logger.debug(f"adaptation proposals request: {proposals}")

        siea_task_id = proposals.siea_task_id
        logger.info(f"siea_task_id: {siea_task_id}")

        # First, calculate the risks of the as-is model
        logger.info("Calculating as-is model risk")
        risk_results = ssm_client.calculate_runtime_risk_vector_full(modelId, RISK_CALC_MODE, False)
        #logger.debug(f"as-is risk_results: {risk_results}")
        asis_risk_level = get_risk_level(risk_results)

        # Initialise adaptation risks array
        adaptation_risks = []

        # Loop through adaptations, apply changes and calc risks
        for adaptation in proposals.adaptation_proposals:
            logger.info(f"adaptation_proposal_id: {adaptation.i_d}")
            changes_made_to_as_is_model = adaptation.changes_made_to_as_is_model
            logger.info(f"changes_made_to_as_is_model: {changes_made_to_as_is_model}")

            # Apply the changes made to the as-is model, returning changes made to SSM model
            ssm_model_changes = apply_changes_made_to_as_is_model(ssm_client, modelId, changes_made_to_as_is_model)
            #logger.debug(f"SSM model changes: {ssm_model_changes}")

            # Calculate the risks of the adaptation
            logger.info(f"Calculating adaptation model risk: {adaptation.i_d}")
            risk_results = ssm_client.calculate_runtime_risk_vector_full(modelId, 'CURRENT', False)
            #logger.info(f"Adaptation {adaptation.i_d} risk_results: {risk_results}")
            adaptation_risk_level = get_risk_level(risk_results)

            adaptation_risk = {
                "adaptation_proposal_id": adaptation.i_d,
                "risk_level": adaptation_risk_level
            }

            adaptation_risks.append(adaptation_risk)

            # Revert the changes made to the SSM model for this adaptation
            revert_changes_made_to_ssm_model(ssm_client, modelId, ssm_model_changes)

        result = { "notification_type": "EvaluationOfAdaptationProposals", "siea_task_id": siea_task_id}

        as_is_risk = {
            "at_id": proposals.as_is_model.atid,
            "risk_level": asis_risk_level
        }

        result["as_is_risk"] = as_is_risk
        result["acceptable_risk_level"] = ACCEPTABLE_RISK_LEVEL
        result["adaptation_risks"] = adaptation_risks

        logger.info("background task ready to post to UDE")
        payload = jsonable_encoder(EvaluationOfAdaptationProposals(**result))
        post_notification(payload)
        logger.info("background task finished posting to UDE")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("background adaptation proposals task has finished")

    except Exception as e:
        logger.error("Exception when calling background task: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.debug(f"releasing session lock for {vjid}")
        await release_session_lock(db_conn, vjid)

    return

def get_risk_level(risk_results):
    risk_vector = risk_results["risk_vector"]
    overall_risk_level = risk_results["overall_risk_level"]
    risk_level = {"overall_risk_level": overall_risk_level, "risk_vector": risk_vector}
    return risk_level

async def bg_evaluate_adaptation_proposal_risks_simulated(proposals: AdaptationProposalsRequest,
        modelId: str, vjid: str, db_conn, ssm_client: SSMClient, verbose=True):

    logger.info("Serving dummy background task for evaluate adaptation proposal risks with POST")
    try:
        # check session is locked for this vjob
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("failed to validate session lock")

        await update_status(db_conn, vjid, "RUNNING")

        # do the long term task
        await asyncio.sleep(2)

        # build ResultOfRiskCalculation
        rv = RiskVector()
        rv.randomise()

        # For now, set the overall risk to the acceptable level, to allow adaptation to be accepted
        overall_risk_level = ACCEPTABLE_RISK_LEVEL
        rv.very_high = 0
        rv.high = 0

        result = { "notification_type": "EvaluationOfAdaptationProposals"}
        as_is_risk = {"at_id": proposals.as_is_model.atid}
        risk_level = {"overall_risk_level": overall_risk_level, "risk_vector": rv}
        as_is_risk["risk_level"] = risk_level
        result["as_is_risk"] = as_is_risk
        result["acceptable_risk_level"] = ACCEPTABLE_RISK_LEVEL
        result["adaptation_risks"] = []
        for adaptation in proposals.adaptation_proposals:
            adaptation_risk = {"adaptation_proposal_id": adaptation.i_d}
            a_rv = RiskVector()
            a_rv.randomise()
            a_rv.very_high = 0
            a_rv.high = 0
            adaptation_risk["risk_level"] = {"risk_vector": a_rv,
                    "overall_risk_level": overall_risk_level}
            result["adaptation_risks"].append(adaptation_risk)

        logger.info("background task ready to post to UDE")
        payload = jsonable_encoder(EvaluationOfAdaptationProposals(**result))
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
