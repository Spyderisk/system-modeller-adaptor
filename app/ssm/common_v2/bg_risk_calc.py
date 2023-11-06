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
##      Created Date :          2021-01-19
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

import json
import time
import copy
import statistics
from collections import defaultdict

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from boolean import Symbol

from app.models.risk import RiskLevelEnum
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.protego.recommendations import CurrentState
from app.models.risk import Risk, State, StateInDB
from ssm_api_client.models.control_strategy import ControlStrategy
from ssm_api_client.models.control_set import ControlSet
from ssm_api_client.models.threat_dto import ThreatDTO

from app.ssm.ssm_client import SSMClient
from app.ssm.cyberkit4sme.shortest_path_mitigation import ShortestPathMitigation

from app.core.config import RISK_CALC_MODE

from fastapi.logger import logger

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"

def bg_calculate_model_risk(modelId: str, ssm_client: SSMClient, risk_mode=RISK_CALC_MODE,
    retain_cs_changes=False, bypass=False):
    """ calculate model risk """

    p_start = time.perf_counter()

    risk_mode = str(risk_mode)

    # We assume we have a session lock
    logger.info(f"bg job calculate model risk {modelId}")
    try:
        p_rec_start = time.perf_counter()

        risk_calc = ShortestPathMitigation(ssm_client, modelId, risk_mode)

        risk_calc.prepare_datasets_risk()

        p_alg_start = time.perf_counter()

        result = risk_calc.existing_state

        p_alg_finish = time.perf_counter()

        logger.debug(f"Calculate model risk time stats: {p_alg_finish - p_alg_start}, overhead {p_alg_start - p_rec_start} sec")

        json_response = jsonable_encoder(result)
        #logger.debug(f"risk_response: {json.dumps(json_response, indent=4, sort_keys=False)}")

        # update job status
        #await update_status(db_conn, vjid, "FINISHED")
        logger.info("creating attack path plots has finised")

        risk_calc.print_stats()

    except Exception as e:
        logger.error("Exception when calling create path plots: %s\n" % e)
        #await update_status(db_conn, vjid, "FAILED", str(e))
        #TODO raise e
        raise e
    #finally:
    #    logger.info("releasing session lock")
    #    await release_session_lock(db_conn, vjid)

    p_1 = time.perf_counter()
    logger.debug(f"Total time for finding attack path plot call: {round((p_1 - p_start), 3)} sec")

    return result


def bg_calculate_model_risk_simple(modelId: str, ssm_client: SSMClient, risk_mode=RISK_CALC_MODE):
    """ calculate model risk, no need to change CS flags explicitly """

    p_start = time.perf_counter()

    risk_mode = str(risk_mode)

    # We assume we have a session lock
    logger.info(f"bg job calculate model risk {modelId}")
    try:
        p_rec_start = time.perf_counter()

        assets_map = {}
        assets = ssm_client.get_model_assets(modelId)
        logger.debug(f"assets found {len(assets)}")
        for asset in assets:
            assets_map["system#" + asset.uri.split('#')[1]] = asset

        logger.debug("get_risk_vector_full: calling calculate_runtime_risk_vector_full_fast")
        risks = ssm_client.calculate_runtime_risk_vector_full_fast(modelId, risk_mode)

        # fix MS asset info
        for risk in risks['consequences']:
            asset_uri = risk['asset']  # short uri
            try:
                asset = assets_map[asset_uri]
                asset_id = asset.id
                risk['asset'] = {} #initialise asset object
                risk['asset']['identifier'] = asset_id
                risk['asset']['type'] = asset.type[67:]
                risk['asset']['label'] = asset.label
                risk['asset']['uri'] = URI_PREFIX + asset_uri

                identifiers = []
                for meta in asset.metadata:
                    identifiers.append({"key": meta.key, "value": meta.value})

                risk['asset']['additional_properties'] = identifiers
            except KeyError as kerr:
                logger.debug(f"cannot find asset: {asset_uri}, {kerr}")
                risk['asset']['identifier'] = "0"
                risk['asset']['type'] = 'unknown'
            risk['uri'] = URI_PREFIX + risk['uri']

        result = State(**risks)

        p_alg_finish = time.perf_counter()

        json_response = jsonable_encoder(result)
        #logger.debug(f"risk_response: {json.dumps(json_response, indent=4, sort_keys=False)}")

        # update job status
        #await update_status(db_conn, vjid, "FINISHED")
        logger.info("creating attack path plots has finised")

    except Exception as e:
        logger.error("Exception when calling caclculate risk: %s\n" % e)
        #await update_status(db_conn, vjid, "FAILED", str(e))
        #TODO raise e
        raise e
    #finally:
    #    logger.info("releasing session lock")
    #    await release_session_lock(db_conn, vjid)

    p_1 = time.perf_counter()
    logger.debug(f"Total time for finding attack path plot call: {round((p_1 - p_start), 3)} sec")

    return result


