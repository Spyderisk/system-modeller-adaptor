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
from boolean import Symbol, AND

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from boolean import Symbol, AND, OR

from app.ssm.ssm_client import SSMClient

from app.models.graph import SVGPlot, StoredSVGPlotInDB
from app.models.protego.recommendations import CurrentState
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.protego.recommendations import StoredRecInDB
from app.models.risk import Risk, State
from app.models.risk import Risk, State, StateInDB
from app.models.risk import RiskLevelEnum
from app.models.session import SessionLock, SessionLockEnum

from ssm_api_client.models.control_set import ControlSet
from ssm_api_client.models.control_strategy import ControlStrategy
from ssm_api_client.models.threat import Threat
from ssm_api_client.models.threat_dto import ThreatDTO

from app.ssm.cyberkit4sme.bg_calculate_risk import calculate_risk
from app.ssm.cyberkit4sme.bg_process_state_reports import process_state_reports
from app.ssm.cyberkit4sme.shortest_path import ShortestPathDataset, ThreatTree
from app.ssm.cyberkit4sme.shortest_path_graph import plot_rec_csg
from app.ssm.cyberkit4sme.shortest_path_mitigation import ShortestPathMitigation

from app.ssm.protego.bg_rollback_utils import restore_twas, clear_twas

from app.crud.store import release_session_lock, get_session
from app.crud.store import store_plot
from app.crud.store import update_status, get_vjob, store_rec, store_state

from fastapi.logger import logger


MAX_THREATS = 10

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"
FUTURE_RISK = False
LIMIT_TO_SHORTEST_PATH = True  # compute the logical expressions to only include aspects relating to the nodes on the shortest paths

async def bg_shortest_path_recommendation(modelId: str, vjid: str, db_conn,
        ssm_client: SSMClient, risk_mode='CURRENT'):
    """ calculate recommendations using shortest path tree """

    p_start = time.perf_counter()

    risk_mode = str(risk_mode)

    # We assume we have a session lock
    logger.info(f"bg job shortest path mitigation {modelId}")
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        logger.info("Part X calculating recommendations")

        await update_status(db_conn, vjid, "RUNNING")

        shortest_path = ShortestPathMitigation(ssm_client, modelId, risk_mode)

        p_rec_start = time.perf_counter()
        shortest_path.prepare_datasets()

        await update_status(db_conn, vjid, "RUNNING")

        # new recommendations algorithm
        p_alg_start = time.perf_counter()
        shortest_path.algorithm_shortest_path()

        p_alg_finish = time.perf_counter()
        logger.debug(f"Recommendations time stats: {p_alg_finish - p_alg_start}, overhead {p_alg_start - p_rec_start} sec")

        vul_recommendation = shortest_path.get_recommendations_obj()

        #logger.debug(f"storing recommendation: {vul_recommendation}")
        rec = await store_rec(db_conn, vjid, vul_recommendation)
        logger.debug("storing recommendation done")

        json_response = jsonable_encoder(vul_recommendation)
        logger.info("\n\n\n==========RECOMMENDATIONS==============")
        logger.info(f"JSON SUPPORT {json.dumps(json_response, indent=4, sort_keys=False)}")
        logger.info("\n\n\n=======================================")

        logger.debug("storing recommendation plots")
        for svg_plot in shortest_path.get_recommendation_plots():
            plot = await store_plot(db_conn, vjid, svg_plot)
            logger.debug(f"storing plot recommendation id {svg_plot.recid} done")
            logger.debug(f"storing plot type {type(svg_plot)} done")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("recommendations has finised")

        shortest_path.print_stats()

    except Exception as e:
        logger.error("Exception when calling shortest path mitigation: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
        #TODO raise e
        raise e
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    p_1 = time.perf_counter()
    logger.debug(f"Total time for risk shortest path mitigation call: {round((p_1 - p_start), 3)} sec")

    return


async def bg_shortest_path_recommendation_combined(modelId: str, vjid: str, db_conn,
        ssm_client: SSMClient, risk_mode='CURRENT'):
    """ calculate recommendations using shortest path tree """

    p_start = time.perf_counter()

    risk_mode = str(risk_mode)

    # We assume we have a session lock
    logger.info("bg job calculating recommendations combined")
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        # Check whether the system model exists (via basic model info)
        model = ssm_client.get_model_info(modelId)
        assert (model is not None)
        logger.info("passed check model found OK")

        await update_status(db_conn, vjid, "RUNNING")
        # STEP I: empty stacked TWA changes
        await clear_twas(modelId, db_conn)
        await update_status(db_conn, vjid, "RUNNING")

        # STEP II: process reports
        await process_state_reports(modelId, ssm_client, db_conn)
        await update_status(db_conn, vjid, "RUNNING")

        # STEP III: run the recommendations algorithm
        shortest_path = ShortestPathMitigation(ssm_client, modelId, risk_mode)

        p_rec_start = time.perf_counter()
        shortest_path.prepare_datasets()

        await update_status(db_conn, vjid, "RUNNING")

        # new recommendations algorithm
        p_alg_start = time.perf_counter()
        shortest_path.algorithm_shortest_path()

        p_alg_finish = time.perf_counter()
        logger.debug(f"Recommendations time stats: {p_alg_finish - p_alg_start}, overhead {p_alg_start - p_rec_start} sec")

        vul_recommendation = shortest_path.get_recommendations_obj()

        #logger.debug(f"storing recommendation: {vul_recommendation}")
        rec = await store_rec(db_conn, vjid, vul_recommendation)
        logger.debug("storing recommendation done")

        json_response = jsonable_encoder(vul_recommendation)
        logger.info("\n\n\n==========RECOMMENDATIONS==============")
        logger.info(f"JSON SUPPORT {json.dumps(json_response, indent=4, sort_keys=False)}")
        logger.info("\n\n\n=======================================")

        logger.debug("storing recommendation plots")
        for svg_plot in shortest_path.get_recommendation_plots():
            plot = await store_plot(db_conn, vjid, svg_plot)
            logger.debug(f"storing plot recommendation id {svg_plot.recid} done")
            logger.debug(f"storing plot type {type(svg_plot)} done")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("recommendations has finised")

        shortest_path.print_stats()

    except Exception as e:
        logger.error("Exception when calling shortest path mitigation: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
        #TODO raise e
        raise e
    finally:
        # STEP IV: Rollback TWA changes:
        await restore_twas(modelId, ssm_client, db_conn)

        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    p_1 = time.perf_counter()
    logger.debug(f"Total time for risk shortest path mitigation call: {round((p_1 - p_start), 3)} sec")

    return

