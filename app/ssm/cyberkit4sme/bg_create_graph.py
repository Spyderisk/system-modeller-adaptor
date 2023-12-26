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

from boolean import Symbol, AND, OR

from app.models.risk import RiskLevelEnum
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.protego.recommendations import CurrentState
from app.models.protego.recommendations import StoredRecInDB
from app.models.graph import SVGPlot, StoredSVGPlotInDB
from app.models.risk import Risk, State, StateInDB
from app.models.session import SessionLock, SessionLockEnum
from ssm_api_client.models.control_strategy import ControlStrategy
from ssm_api_client.models.control_set import ControlSet
from ssm_api_client.models.threat import Threat
from ssm_api_client.models.threat_dto import ThreatDTO

from app.ssm.ssm_client import SSMClient
from app.ssm.cyberkit4sme.shortest_path import ShortestPathDataset, ThreatTree
from app.ssm.cyberkit4sme.shortest_path_graph import plot_rec_csg
from app.ssm.cyberkit4sme.shortest_path_mitigation import ShortestPathMitigation

from app.crud.store import update_status, get_vjob, store_rec, store_state
from app.crud.store import release_session_lock, get_session
from app.crud.store import store_plot

from app.ssm.cyberkit4sme.shortest_path_graph import plot_graph

from boolean import Symbol, AND, OR

import traceback

from fastapi.logger import logger

MAX_THREATS = 10

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"

INFINITY = 99999999

# General plot options:
FUTURE_RISK = False
LIMIT_TO_SHORTEST_PATH = True  # compute the logical expressions to only include aspects relating to the nodes on the shortest paths

async def bg_create_attack_path(modelId: str, vjid: str, db_conn,
        ssm_client: SSMClient, risk_mode='CURRENT', output_format:str='svg'):
    """ create attak path plot using  shortest path algorithm """

    p_start = time.perf_counter()

    risk_mode = str(risk_mode)

    # We assume we have a session lock
    logger.info(f"bg job create attack path plot {modelId}")
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        path_plot = ShortestPathMitigation(ssm_client, modelId, risk_mode)

        logger.info("Part X finding attack path plot")

        p_rec_start = time.perf_counter()

        path_plot.prepare_datasets()

        await update_status(db_conn, vjid, "RUNNING")

        # new recommendations algorithm
        p_alg_start = time.perf_counter()

        svg_graph = path_plot.create_first_pass_plot(output_format=output_format)

        p_alg_finish = time.perf_counter()
        logger.debug(f"Create attack path plots time stats: {p_alg_finish - p_alg_start}, overhead {p_alg_start - p_rec_start} sec")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("creating attack path plots has finised")

        path_plot.print_stats()

    except Exception as e:
        logger.error("Exception when calling create path plots: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
        traceback.print_exc()
        #TODO raise e
        raise e
    #finally:
    #    logger.info("releasing session lock")
    #    await release_session_lock(db_conn, vjid)

    p_1 = time.perf_counter()
    logger.debug(f"Total time for finding attack path plot call: {round((p_1 - p_start), 3)} sec")

    return svg_graph


