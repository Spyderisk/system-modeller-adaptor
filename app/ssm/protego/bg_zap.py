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
##      Created By :            Samuel Senior
##      Created Date :          2021-05-18
##      Created for Project :   ProTego
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

from app.models.protego.zappies import Zappies, Site, Alert, Instance, Method
from app.models.protego.vulnerability import Identifier as VulIdentifier
from app.models.risk import RiskVector, Asset
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.session import SessionLockEnum

from app.ssm.ssm_client import SSMClient, TWALevel

from app.crud.store import release_session_lock, get_session
from app.crud.store import update_status, get_vjob

from app.ssm.protego.bg_rollback_utils import store_twas

from app.ssm.protego.bg_alert_mappings import ZapMappings

from fastapi.logger import logger


def compose_causation(alert):
    """ compose alert causation string """
    cause = ""
    if alert.cweid:
        cause += f" cweid: {alert.cweid}"
    if alert.wascid:
        cause += f" wascid: {alert.wascid}"
    if alert.riskcode:
        cause += f" riskcode: {alert.riskcode}"
    return cause

# /models/{model_id}/aset/zap
async def bg_update_zap_vulnerabilities(model_id: str, zappies: Zappies, vjid: str,
        db_conn, ssm_client: SSMClient, authenticated_scan: bool):

    p_zap_start = time.perf_counter()

    logger.info(f"update_zap_vulnerability {model_id}")
    try:
        session = await get_session(db_conn, model_id)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to verify lock")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed model found check")

        # validate model
        if not ssm_client.validate_model(model_id):
            logger.error(f"ERROR: model not validated {model_id}")
            return ('Precondition Failed', 412)

        logger.info(f'A new request has been received for {model.name} with id {model.id}.')

        logger.info("passed model validation check")

        # Check the validity of the ZAP version. Only ZAP 2.10.0 is currently supported.
        assert (zappies.version == "2.10.0")

        zapMappings = ZapMappings("app/static/mappings/cwec.csv", "app/static/mappings/wasc.csv",
                                  "app/static/mappings/capec.csv", "app/static/mappings/owasp_top10_2010.csv")

        # Get the set identifiers from the ZAP report to uniquely identify
        # and retrieve the corresponding asset in the SSM model
        for site in zappies.site:
            logger.info(f"site found {site.host}")

            logger.info(f"asset identifiers {site.host}, {site.port}")
            identifiers = {'host': site.host, 'port': site.port}

            identifiers = [{'key': 'host', 'value': site.host},
                           {'key': 'port', 'value': site.port}]

            logger.debug(f"recomposed identifiers: {identifiers}, {type(identifiers)}")

            asset = ssm_client.find_ssm_asset(identifiers, model_id)
            #####
            # Should this not be a raise?
            if not asset:
                #return 'Model asset not found',
                logger.warn(f'Model asset not found for identifier: {identifiers}')
                continue

            logger.debug(f"Examining asset: {asset.id}, {asset.label}")

            # Get asset's metadata
            #asset_meta = ssm_client.get_asset_metadata(asset.id, model_id)
            #logger.info("got asset_meta")

            # Retrieve current TWAs from the retrieved asset
            current_twas = asset.trustworthiness_attribute_sets
            logger.info(f"Retrieved current TWAs size: {len(current_twas)}")

            # Get the list of alerts for the given asset
            logger.info(f"Number of alerts to parse {len(site.alerts)}")

            # Get the TWAs specific to the ZAP mapping type
            twasToUpdate = zapMappings.getBaseTWAs()

            skippedAlerts = {}
            for alert in site.alerts:
                logger.info(f'Processing alert {alert.pluginid}: \"{alert.name}\"')

                # Get the new TWA(s) from an alert
                newTWAs = zapMappings.processZapAlerts(alert, authenticated_scan)

                # Check if new TWA levels are worse than current update value, if so then replace,
                # if not then skip
                for twa, newTWAValue in newTWAs.items():
                    if newTWAs[twa] == None:
                        pass
                    elif twasToUpdate[twa] == None:
                        logger.info(f"[alert {alert.pluginid}] Setting alert TWA {twa} to {newTWAValue}")
                        twasToUpdate[twa] = newTWAValue
                    elif TWALevel[newTWAValue.upper()] < TWALevel[twasToUpdate[twa].upper()]:
                        logger.info(f"[alert {alert.pluginid}] Changing alert TWA {twa}: {twasToUpdate[twa]} -> {newTWAValue}")
                        twasToUpdate[twa] = newTWAValue
                    else:
                        logger.info(f"[alert {alert.pluginid}] Change to alert TWA {twa} does not make TWA worse, keeping previous value")
                        skippedAlerts[alert.pluginid] = f"Change to alert TWA {twa} does not make TWA worse, keeping previous value"

            logger.info(f"{len(site.alerts) - len(zapMappings._skippedAlerts['zapUnsupported'])}/{len(site.alerts)} ZAP alerts processed, {len(zapMappings._skippedAlerts['zapUnsupported'])}/{len(site.alerts)} unable to be processed")

            logger.info(f"Alert TWA set gained from ZAP alerts: {twasToUpdate}")

            stem = f"http://it-innovation.soton.ac.uk/ontologies/" \
                    f"trustworthiness/domain#TrustworthinessLevel"

            logger.info("Updating asset TWA set for worse TWAs of alert TWA set")
            cause = compose_causation(alert)
            for twa, twaLevel in twasToUpdate.items():
                if twaLevel != None:
                    zapAlertTWAUri = stem + twaLevel
                    ssm_client.update_twas(twa, current_twas, zapAlertTWAUri, asset.id, asset.label, cause, model_id)

            logger.info("Asset TWAs updated from passed in ZAP alerts")

        # validate model
        #if not ssm_client.validate_model(model_id):
        #    error_msg = "ERROR: zap failed to validate modified model"
        #    logger.error(error_msg)
        #    await update_status(db_conn, vjid, "FAILED", error_msg)
        #    raise HTTPException(status_code=412, detail="ZAP failed to validate model")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("Finished updating TWAs from ZAP report")

        if ssm_client.twa_changes:
            logger.debug(f"Recorded TWA changes len: {len(ssm_client.twa_changes)}, {ssm_client.twa_changes}")
            await store_twas(ssm_client, db_conn)
        else:
            logger.debug("no TWA changes recorded")

        p_zap_finish = time.perf_counter()
        logger.debug(f"Time stats: ZAP completed in {p_zap_finish - p_zap_start} sec")

    except Exception as e:
        logger.error(f"Exception when calling update_zap_vulnerabilities: {e}")
        await update_status(db_conn, vjid, "FAILED", str(e))
        raise HTTPException(status_code=503, detail="find asset failed")
    finally:
        logger.info("Releasing session lock")
        await release_session_lock(db_conn, vjid)

    return
