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
##      Created Date :          2021-04-29
##      Created for Project :   FogProtect
##
##///////////////////////////////////////////////////////////////////////


import logging
from typing import Optional, Any, List
from fastapi import APIRouter, Body, Depends, Path, Query, HTTPException
from fastapi import status
from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks
from bson.objectid import ObjectId

from app.crud.store import (create_vjob, get_vjob)
from app.crud.store import (acquire_session_lock, release_session_lock, update_status)

from app.db.mongodb import AsyncIOMotorClient, get_database
from app.ssm.ssm_client import SSMClient
from app.ssm.ssm_base import get_ssm_base
from app.ssm.fogprotect.bg_fogprotect import bg_fp_task, bg_fp_task_notify
from app.ssm.fogprotect.bg_notify_immediate_action_event import bg_notify_immediate_action_event
from app.ssm.fogprotect.bg_evaluate_event_risks import bg_evaluate_event_risks
from app.ssm.fogprotect.bg_adaptation_executed import bg_adaptation_executed
from app.ssm.fogprotect.bg_evaluate_adaptation_proposal_risks import bg_evaluate_adaptation_proposal_risks
from app.ssm.fogprotect.bg_reset import bg_reset

from app.models.vjob import VJobStatus, VJobInDB
from app.models.fogprotect.adaptation import (AdaptationProposalsRequest, AdaptationExecutedRequest, AdaptationResponse)
from app.models.fogprotect.event_notification import EventNotification, Reset, Status

from fastapi.logger import logger

import time

router = APIRouter(tags=['SIEA'])

responses = {
        404: {"description": "Item not found"},
        423: {"description": "Resource locked, by another process try again later."},
        }

@router.post("/models/{modelId}/notify-immediate-action-event",
        response_model=VJobStatus,
        responses={
            404: {"description": "Item not found"},
            423: {"description": "Resource locked, by another process try again later."},
        },
        status_code=status.HTTP_202_ACCEPTED)
async def immediate_action_event(
        bg_tasks: BackgroundTasks,
        e_notification: EventNotification,
        modelId: str = Path(..., title="ModelId webkey"),
        db: AsyncIOMotorClient = Depends(get_database),
        ssm: SSMClient = Depends(get_ssm_base),
        ):
    """
    Notify immediate action event (e.g. "lock down").

    URL contains {modelId} = web key of model, hard-to-guess string
    distributed out of band to partners

    Body = door open event, for example:

        {
            "NotificationType": "ImmediateAction",
            "SieaTaskId": 28,
            "Vulnerabilities": [
                {
                    "ChangesMadeToAsIsModel": [
                        {
                            "ObjectToIdentify": {
                                "name": "FiaB Shipping Container",
                                "type": "fogprotect.adaptation.ComputingContinuumModel.PrivateSpace",
                                "atid": "//@tosca_nodes_root.31"
                            },
                            "Changes": [
                                {
                                    "ChangeType": "CHANGE",
                                    "AttributeChanged": "trustworthy",
                                    "AttributeType": "Trustworthy",
                                    "AttributeOldValue": "HIGH",
                                    "AttributeNewValue": "LOW"
                                }
                            ]
                        }
                    ],
                    "EventName": "DoorOpen",
                    "EventStatus": "FullLockDown",
                    "Timestamp": 1615369966017,
                    "Offset": 24,
                    "Partition": 0
                }
            ]
        }

    Actions:

    1) Lock SSM model (prevent concurrent requests making changes to SSM model)

    2) Immediately pass "lock down" event message to WP5 at ip:port/fogprotect/adaptationcoordinator/notify
    via POST to WP5 as follows:

            {
                "NotificationType": "ImmediateAction",
                "EventName": "DoorOpen",
                "ContainerStatus": "FullLockdown",
                "SieaTaskId": 28
            }

    3) Update SSM model as per request body, lowering the trustworthiness level of the appropriate
    Trustworthiness Attribute Set (TWAS) on the SSM model asset identified by the "ObjectToIdentify"

       (TODO: create a static mapping from ObjectToIdentify -> SSM asset and "Door open" event -> TWAS URI in SSM model)

    4) Release lock on model
    """

    logger.info(f"Received immediate action event: {e_notification}")

    vjob = await create_vjob(db, {"modelId": modelId})

    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to create evaluate immediate action event job")

    vjob_id = str(vjob.id)

    logger.info(f"Evaluate immediate action event job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                detail="Resource is locked by another process, try again later.")

    logger.info(f"Starting bg immediate action event job")

    bg_tasks.add_task(bg_notify_immediate_action_event,
            e_notification, modelId, vjob_id, db, ssm)

    logger.info(f"Asynchronous return from immediate action event job {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}

@router.post("/models/{modelId}/evaluate-event-risks",
        response_model=VJobStatus,
        responses={
            404: {"description": "Item not found"},
            423: {"description": "Resource locked, by another process try again later."},
        },
        status_code=status.HTTP_202_ACCEPTED)
async def evaluate_risks_due_to_event(
        bg_tasks: BackgroundTasks,
        e_notification: EventNotification,
        modelId: str = Path(..., title="ModelId webkey"),
        db: AsyncIOMotorClient = Depends(get_database),
        ssm: SSMClient = Depends(get_ssm_base),
        rec: bool = False,
        ):
    """
    Evaluate risks due to event occurring (e.g. "door open")

    URL contains {modelId} = web key of model, hard-to-guess string
    distributed out of band to partners

    Body = door open event, etc

    TODO: define body schema (similar to ImmediateActionEventRequest?)


    :param str model_webkey: the webkey of the SSM model corresponding to the live system

    :param bool rec: run the recommendation algorithm

    Actions:

    Lock SSM model (prevent concurrent requests)

    Update SSM model as per body and mapping between event type in body and SSM
    model

    Calculate risks for model

    Release lock on model

    POST result of risk calc to WP5 at
    ip:port/fogprotect/adaptationcoordinator/notify Body of push to WP5 = risks
    list, overall risk level, risk vector, etc N.B. A "Risk" corresponds to a
    Misbehabiour on an Asset in the SSM model

    Example request to WP5:

        {
            "NotificationType": "ResultOfRiskCalculation",
            "SieaTaskId": 28,
            "Risks": [
                {
                "ObjectToIdentify": {
                    "Name": "string",
                    "Type": "string",
                    "AtID": "string"
                },
                "RiskName": "string",
                "RiskDescription": "string",
                "RiskImpact": "string",
                "RiskLikelihood": "string",
                "RiskLevel": "string"
                }
            ],
            "OverallRiskLevel": "string",
            "RiskVector": {
                "VeryHigh": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "VeryLow": 0
            },
            "AcceptableRiskLevel": "string"
        }

    N.B. If service is currently busy calculating risks return 503 response
    """

    logger.info(f"Received evaluate event risks call: {e_notification}")

    vjob = await create_vjob(db, {"modelId": modelId})

    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to create evaluate event risks job")

    vjob_id = str(vjob.id)
    logger.info(f"Evaluate event risks job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                detail="Resource is locked by another process, try again later.")

    logger.info(f"Starting bg evaluate event risks job")

    ####### add background job call here #################
    bg_tasks.add_task(bg_evaluate_event_risks, e_notification, modelId, vjob_id, db, ssm, rec)

    logger.info(f"Asynchronous return from evaluate event risks job {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}


@router.post("/models/{modelId}/evaluate-adaptation-proposal-risks",
        response_model=VJobStatus,
        responses={
            404: {"description": "Item not found"},
            423: {"description": "Resource locked, by another process try again later."},
        },
        status_code=status.HTTP_202_ACCEPTED)
async def evaluate_adaptation_proposal_risks(
        bg_tasks: BackgroundTasks,
        adaptation_proposal: AdaptationProposalsRequest,
        modelId: str = Path(..., title="ModelId webkey"),
        db: AsyncIOMotorClient = Depends(get_database),
        ssm: SSMClient = Depends(get_ssm_base),
        ):
    """
    Evaluate risks for one or more adaptation proposals.

    URL contains {modelId} = web key of model, hard-to-guess string distributed
    out of band to partners

    Body: AdaptationRequest (defined by agreement with WP5) Jan to send shcema
    of body for set of adaptation proposals

    Actions:

    Lock SSM model (prevent concurrent requests)

    For each Adaptation Proposal: Update SSM model as per mapping between
    adaptation and SSM model, Evaluate risk levels & record results, Roll back
    SSM model

    Release lock on model

    When all are done we POST results of risk levels per adaptation proposal to
    WP5 at ip:port/fogprotect/adaptationcoordinator/notify Contents of POST
    includes JSON body containing: Risk level of current as-is model,
    Acceptable risk level, Risk levels for each adaptation proposal

    Example request to WP5:

        {
            "NotificationType": "EvaluationOfAdaptationProposals",
            "SieaTaskId": 28,
            "AsIsRisk": {
                "AtId": "string",
                "RiskLevel": {
                    "OverallRiskLevel": "string",
                    "RiskVector": {
                        "Very High": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Very Low": 0
                    }
                }
            },
            "AcceptableRiskLevel": "Medium",
            "AdaptationRisks": [
                {
                "AdaptationProposalId": "string",
                "RiskLevel": {
                    "OverallRiskLevel": "string",
                    "RiskVector": {
                        "Very High": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Very Low": 0
                    }
                }
              }
            ]
        }

    """

    logger.info("Received evaluate adaptation proposal risks call")
    logger.debug(f"adaptation_proposal: {adaptation_proposal}")

    vjob = await create_vjob(db, {"modelId": modelId})

    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to create evaluate adaptation proposal risks job")

    vjob_id = str(vjob.id)

    logger.info(f"Evaluate adaptation proposal risks job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                detail="Resource is locked by another process, try again later.")

    logger.info(f"Starting bg evaluate adaptation proposal risks job")

    ####### add backgournd job call here #################
    bg_tasks.add_task(bg_evaluate_adaptation_proposal_risks,
            adaptation_proposal, modelId, vjob_id, db, ssm)

    logger.info(f"Asynchronous return from evaluate proposal risks job {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}


@router.post("/models/{modelId}/notify-adaptation-executed",
        response_model=VJobStatus,
        responses={
            404: {"description": "Item not found"},
            423: {"description": "Resource locked, by another process try again later."},
        },
        status_code=status.HTTP_202_ACCEPTED)
async def notify_adaptation_executed(
        bg_tasks: BackgroundTasks,
        adaptation: AdaptationExecutedRequest,
        modelId: str = Path(..., title="ModelId webkey"),
        db: AsyncIOMotorClient = Depends(get_database),
        ssm: SSMClient = Depends(get_ssm_base),
        ):
    """

    Notify WP7 that system adaptation has taken place. Calculate risks and send
    to WP5.

    URL contains {modelId} = web key of model, hard-to-guess string distributed
    out of band to partners

    Body: AdaptationRequest (selected adaptation proposal) This is forwarded by
    the SIEA and is in the same format as one of the adaptation proposals from
    WP5.

    Actions:

    Lock SSM model (prevent concurrent requests)

    Update SSM model as per request body and run risk calculation.

    DO NOT roll back changes to SSM model because this is confirmation of a
    real adaptation (rather than a proposal)

    Release lock on model

    POST result of risk calc to WP5 at
    ip:port/fogprotect/adaptationcoordinator/notify Body of push to WP5 = risks
    list, overall risk level, risk vector, etc N.B. A "Risk" corresponds to a
    Misbehabiour on an Asset in the SSM model

    Example request to WP5:

        {
            "NotificationType": "EvaluationOfAdaptation",
            "SieaTaskId": 28,
            "AsIsRisk": {
                "@id": "string",
                "RiskLevel": {
                "OverallRiskLevel": "string",
                "RiskVector": {
                    "Very High": 0,
                    "High": 0,
                    "Medium": 0,
                    "Low": 0,
                    "Very Low": 0
                }
              }
            },
            "AcceptableRiskLevel": "Medium",
            "AdaptationRisk": {
                "AdaptationProposalId": "string",
                "RiskLevel": {
                    "OverallRiskLevel": "string",
                    "RiskVector": {
                        "Very High": 0,
                        "High": 0,
                        "Medium": 0,
                        "Low": 0,
                        "Very Low": 0
                    }
                },
                "AcceptableRiskLevel": "string"
            }
        }

    """

    logger.info("Received notify adaptation executed call")
    logger.debug(f"adaptation: {adaptation}")

    vjob = await create_vjob(db, {"modelId": modelId})

    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to create notified-adaptation-executed job")

    vjob_id = str(vjob.id)

    logger.info(f"Notify adaptation executed job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                detail="Resource is locked by another process, try again later.")

    logger.info(f"Starting bg notify adaptation executed job")

    ####### add backgournd job call here #################
    bg_tasks.add_task(bg_adaptation_executed, adaptation, modelId, vjob_id, db, ssm)

    logger.info(f"Asynchronous return from notify adaptation executed job {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}

@router.post("/models/{modelId}/reset",
        response_model=VJobStatus,
        responses={
            404: {"description": "Item not found"},
            423: {"description": "Resource locked, by another process try again later."},
        },
        status_code=status.HTTP_202_ACCEPTED)
async def evaluate_risks_due_to_event(
        bg_tasks: BackgroundTasks,
        reset: Reset,
        modelId: str = Path(..., title="ModelId webkey"),
        db: AsyncIOMotorClient = Depends(get_database),
        ssm: SSMClient = Depends(get_ssm_base),
        ):
    """
    Reset event. Reset SSM system model back to initial state
    """

    logger.info(f"Received reset event: {reset}")

    vjob = await create_vjob(db, {"modelId": modelId})

    if not vjob:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                detail="Failed to create reset job")

    vjob_id = str(vjob.id)
    logger.info(f"Reset job {vjob}, {vjob_id}")

    # acquire session lock
    lock_acquired = await acquire_session_lock(db, vjob_id)

    if not lock_acquired:
        # update status of job as REJECTED
        await update_status(db, vjob_id, "REJECTED")
        logger.debug("Failed to acquire session lock return 423")
        raise HTTPException(status_code=status.HTTP_423_LOCKED,
                detail="Resource is locked by another process, try again later.")

    logger.info(f"Starting bg reset job")

    ####### add background job call here #################
    bg_tasks.add_task(bg_reset, reset, modelId, vjob_id, db, ssm)

    logger.info(f"Asynchronous return from reset job {vjob.created_at}")

    return {"jobid": vjob_id, "status": vjob.status}


