##///////////////////////////////////////////////////////////////////////
##
## © University of Southampton IT Innovation Centre, 2023
##
## Copyright in this software belongs to University of Southampton
## IT Innovation Centre, Highfield Campus, SO17 1BJ, UK.
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
##      Created Date :          2023-09-18
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////


import json
import time
import copy
import statistics
from collections import defaultdict

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from app.models.session import SessionLock, SessionLockEnum

from ssm_api_client.models.control_strategy import ControlStrategy
from ssm_api_client.models.control_set import ControlSet
from ssm_api_client.models.threat import Threat
from ssm_api_client.models.trustworthiness_attribute_set import TrustworthinessAttributeSet

from app.models.state_report import OperatorEnum
from app.models.state_report import Trustworthiness
from app.models.state_report import ExpiryTypeEnum

from app.ssm.ssm_client import SSMClient

from app.crud.store import update_status, get_vjob, store_rec, store_state
from app.crud.store import release_session_lock, get_session

from app.crud.store_state_report import get_valid_reports
from app.crud.store_state_report import get_expired_reports
from app.crud.store_state_report import remove_state_report

from app.ssm.protego.bg_rollback_utils import store_twas, list_twas, clear_twas

import traceback

from fastapi.logger import logger

async def bg_process_state_reports(model_id: str, vjid: str, ssm, db_conn) -> int:
    """ process pending state reports """

    # We assume we have a session lock
    logger.info(f"bg job process pending reports")
    processed_counter = 0
    try:
        session = await get_session(db_conn, model_id)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        # Check whether the model exists
        #model = ssm_client.get_model_info(model_id)
        #assert (model is not None)
        #logger.info("passed model found check")

        processed_counter = await process_state_reports(model_id, ssm, db_conn)

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("Finished updating state report processing")

    except Exception as e:
        logger.error("Exception when calling process pending state reports: %s\n" % e)
        traceback.print_exc()
        #TODO raise e
        await update_status(db_conn, vjid, "FAILED", str(e))
        raise HTTPException(status_code=503, detail="find asset failed")
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    return processed_counter

def extract_state_report_newest_type(report):
    newest = set()
    if report.expiry:
        for expiry in report.expiry:
            if ExpiryTypeEnum(expiry.type) == ExpiryTypeEnum('newest'):
                label = "None"
                if expiry.label:
                    label = expiry.label
                newest.add(label)
    return newest

def get_twas_for_attribute(twa_dict, twa):
    for tw_key, twas in twa_dict.items():
        if twas.attribute.uri == twa:
            return twas
    return None

def find_invalidated_reports(reports):
    # filter out 'older' newest expiry type reports, delete older ones.
    logger.debug("find invalidated reports, e.g. replaced by newer reports")
    newest = set()
    old_reports = []
    for report in reports:
        if report.expiry:
            # skip report of type "newest" if processed already
            type_newest = extract_state_report_newest_type(report)
            intersection = type_newest & newest
            if not intersection:
                newest |= type_newest
            else:
                logger.debug(f"SKIPPING report newest type label: {newest} ({report.id})")
                old_reports.append(report.id)
                continue
    return  old_reports

async def remove_expired_reports(db_conn, model_id):
    # remove expired reports
    logger.debug("removing expired reports ...")
    expired_report_ids = await get_expired_reports(db_conn, model_id)
    for report_id in expired_report_ids:
        logger.debug(f"removing expired state report {report_id}")
        await remove_state_report(db_conn, report_id)


async def process_state_reports(model_id: str, ssm, db_conn) -> int:
    """ process pending state reports utility """

    logger.debug("processing state reports")

    p_start = time.perf_counter()

    processed_counter = 0

    p_rec_start = time.perf_counter()

    # remove expired reports from DB
    await remove_expired_reports(db_conn, model_id)

    # NB get valid reports, the order of reports is DESCENDING
    reports = await get_valid_reports(db_conn, model_id)

    # filter out 'older' newest expiry type reports, delete older ones.
    invalidated_reports = find_invalidated_reports(reports)

    logger.debug(f"REPORTS found: {len(reports)} vs invalidated {len(invalidated_reports)}")

    cached_twas = {}
    twa_stack = {}

    # loop through reports in reverse order (oldest -> newest) for
    # processing
    for report in reversed(reports):
        if report.id in invalidated_reports:
            logger.debug(f"This report ({report.id}) has been invalidated and will be deleted")
            await remove_state_report(db_conn, report.id)
            continue

        processed_counter += 1
        logger.debug(f"STATE REPORT: {processed_counter}, expiry: {report.expiry}")

        # parse report states
        for item in report.state:
            # check asset id
            asset_id = item.asset.id

            if asset_id is None:
                logger.info(f"No asset id defined. Checking metadata..")
                assert item.asset.properties is not None

                # Extract properties
                properties = []
                for property in item.asset.properties:
                    properties.append({'key': property.key, 'value': property.value})

                # Locate asset with these properties
                asset = ssm.find_ssm_asset(properties, model_id)

                if not asset:
                    logger.warning(f'Model asset not found for identifier: {item.asset.properties}')
                else:
                    logger.info(f"Located asset: {asset.id}")
                    asset_id = asset.id

            # get actual model TWAS
            twa_dict = ssm.get_asset_twas(asset_id, model_id)

            for twa in item.trustworthiness:
                logger.debug(f"proposed TWA change: {twa}")

                twas_uri = twa.trustworthinessAttributeSet

                if twas_uri is None:
                    logger.info(f"No uri for tw: {twa.dict()}")
                    assert twa.trustworthinessAttribute is not None
                    twas = get_twas_for_attribute(twa_dict, twa.trustworthinessAttribute)
                    logger.info(f"Located twas: {twas}")
                    if twas is None:
                        logger.error(f"cannot find TWAS for {twa.trustworthinessAttribute}")
                        continue
                    twas_uri = twas.uri
                    logger.info(f"twas_uri: {twas_uri}")

                #TODO fetch TWA URI, and level
                if twas_uri not in cached_twas:
                    ssm_twa = Trustworthiness(**{'trustworthinessAttributeSet': twas_uri,
                        'level': twa_dict[twas_uri].asserted_tw_level.uri,
                        'operator': '='})
                    logger.debug(f"fetch TWA from SSM : {ssm_twa}")
                    cached_twas[twas_uri] = ssm_twa
                    twa_stack[twas_uri] = {"twa_uri": twas_uri, "asset_id": asset_id,
                            "old_level": twa_dict[twas_uri].asserted_tw_level.uri, "new_level": None}
                else:
                    logger.debug(f"cached twa hit     : {cached_twas[twas_uri]}")

                # start comparing TWA operators for proposed changes
                if OperatorEnum(twa.operator) is OperatorEnum.EQ:
                    logger.debug(f"\tOperator EQ override cached value")
                    if not cached_twas[twas_uri] == twa:
                        logger.debug(f"\t   Not equal, UPDATE TWA level {cached_twas[twas_uri].level[87:]} --> {twa.level[87:]}")
                        cached_twas[twas_uri].level = twa.level
                        twa_stack[twas_uri]["new_level"] = twa.level
                    else:
                        logger.debug(f"\t   TWAS are equal no need to update")
                elif OperatorEnum(twa.operator) is OperatorEnum.GE:
                    logger.debug(f"\tOperator GE found {twa.level[87:]} > {ssm_twa.level[87:]}")
                    if twa > cached_twas[twas_uri]:
                        logger.debug(f"\t   GE found UPDATE TWA level {cached_twas[twas_uri].level[87:]} --> {twa.level[87:]}")
                        cached_twas[twas_uri].level = twa.level
                        twa_stack[twas_uri]["new_level"] = twa.level
                    else:
                        logger.debug("\t   GE condition not satisfied")
                elif OperatorEnum(twa.operator) is OperatorEnum.LE:
                    logger.debug(f"\tOperator LE found {twa.level[87:]} < {ssm_twa.level[87:]}")
                    if twa < cached_twas[twas_uri]:
                        logger.debug(f"\t   LE found UPDATE TWA level {cached_twas[twas_uri].level[87:]} --> {twa.level[87:]}")
                        cached_twas[twas_uri].level = twa.level
                        twa_stack[twas_uri]["new_level"] = twa.level
                    else:
                        logger.debug("\t   LE condition not satisfied")
                else:
                    logger.error(f"\tBAD OPERATOR: {twa.operator}")

    logger.debug(f"Reports processed: {processed_counter}, cached states: {len(cached_twas)}")

    # apply TWAS changes
    logger.debug("apply TWAs changes")
    for twas in twa_stack.values():
        if twas['new_level']:
            logger.debug(f"TODo -> {twas}")
            ssm.do_twas(model_id, twas, "SCAN REPORT", "unknown level")

    # store applied TWAS changes to db
    logger.debug("store applied TWA changes to DB")
    if ssm.twa_changes:
        logger.debug(f"Storing TWAS changes to database")
        await store_twas(ssm, db_conn)
    else:
        logger.debug("no TWAS changes recorded")

    logger.info("Finished updating state report processing")

    p_1 = time.perf_counter()
    logger.debug(f"Total time for processing pending state reports: {round((p_1 - p_start), 3)} sec")

    return processed_counter


