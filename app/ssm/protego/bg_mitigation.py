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

import os
import asyncio
import aiohttp
import json
import datetime
import time
import copy
import math
import statistics
import itertools
from collections import defaultdict
from bson.objectid import ObjectId

from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder

from app.models.protego.vulnerability import CVSS, Identifier, Vulnerability
from app.models.risk import RiskVector, Asset, RiskLevelEnum
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.protego.recommendations import StoredRecInDB
from app.models.risk import State, StateInDB
from app.models.session import SessionLock, SessionLockEnum
from ssm_api_client.models.control_strategy import ControlStrategy
from ssm_api_client.models.control_set import ControlSet
from ssm_api_client.models.threat import Threat

from app.clients.kafka_client import connect_n_publish
from app.core.config import KAFKA_ENABLED, MAX_THREATS

from app.ssm.ssm_client import SSMClient
from ssm_api_client.exceptions import ApiException

from app.crud.store import update_status, get_vjob, store_rec, store_state
from app.crud.store import release_session_lock, get_session

from fastapi.logger import logger

from kafka import KafkaProducer

async def bg_mitigation(modelId: str, vjid: str, db_conn, ssm_client: SSMClient):

    p_start = time.perf_counter()

    # We assume we have a session lock
    logger.info(f"bg job calculate risk/mitigation {modelId}")
    try:
        session = await get_session(db_conn, modelId)
        if session.task_id != vjid or session.status != SessionLockEnum.locked:
            logger.error(f"Session lock does not match task ID {vjid}")
            raise Exception("model failed to validate")

        await update_status(db_conn, vjid, "RUNNING")

        miti = RecommendationsAlgorithm(ssm_client, modelId)

        logger.info("Part A calculating risk")

        p_risk_start = time.perf_counter()

        risk_response = miti.get_risk_vector_full()
        json_response = jsonable_encoder(risk_response)
        logger.debug(f"risk_calculation: {json.dumps(json_response, indent=4, sort_keys=False)}")

        if KAFKA_ENABLED:
            logger.info("PUSH risk calculation to KAFKA")
            try:
                connect_n_publish('risk', json.dumps(json_response))
            except Exception as ex:
                msg = f"Exception while publishing risk message to kafka: {ex}"
                logger.error(msg)
                await update_status(db_conn, vjid, "RUNNING", str(msg))

        logger.debug("storing risk")
        rec = await store_state(db_conn, vjid, risk_response)
        logger.debug("storing risk is done")

        await update_status(db_conn, vjid, "RUNNING")

        p_risk_finish = time.perf_counter()
        logger.debug(f"risk calculation time: {p_risk_finish - p_risk_start} sec")

        logger.info("Part B calculating recommendations")

        p_rec_start = time.perf_counter()

        miti.prepare()
        #raise Exception("debugging exception to stop recommendations algorithm")

        # new recommendations algorithm
        p_alg_start = time.perf_counter()
        miti.algorithm_ms()
        p_alg_finish = time.perf_counter()
        logger.debug(f"Recommendation time stats: {p_alg_finish - p_alg_start}, overhead {p_alg_start - p_rec_start} sec")

        vul_recommendation = miti.get_recommendations_obj()
        json_response = jsonable_encoder(vul_recommendation)

        logger.debug("storing recommendation")
        rec = await store_rec(db_conn, vjid, vul_recommendation)
        logger.debug("storing recommendation done")

        if KAFKA_ENABLED:
            try:
                connect_n_publish('recommendations', json.dumps(json_response))
            except Exception as ex:
                msg = f"Exception while publishing recommendations to kafka: {ex}"
                logger.error(msg)
                await update_status(db_conn, vjid, "RUNNING", str(msg))

        logger.info("\n\n\n==========RECOMMENDATIONS==============")
        logger.info(f"JSON SUPPORT {json.dumps(json_response, indent=4, sort_keys=False)}")
        logger.info("\n\n\n=======================================")

        # update job status
        await update_status(db_conn, vjid, "FINISHED")
        logger.info("recommendations has finised")

        miti.print_stats()

    except ApiException as ex:
        logger.error("ApiException when calling risk vector: %s\n" % ex)
        body = json.loads(ex.body)
        reason=f"Call failed with SSM error: {body['message']}"
        await update_status(db_conn, vjid, "FAILED", reason)
    except Exception as e:
        logger.error("Exception when calling mitigation: %s\n" % e)
        await update_status(db_conn, vjid, "FAILED", str(e))
    finally:
        logger.info("releasing session lock")
        await release_session_lock(db_conn, vjid)

    p_1 = time.perf_counter()
    logger.debug(f"Total time for risk mitigation call: {round((p_1 - p_start), 3)} sec")

    return


class RecommendationsAlgorithm():
    def __init__(self, ssm_client, model_id):
        self.ssm_client = ssm_client
        self.model_id = model_id
        self.assets_map = {}
        self.classified_csgs = defaultdict(list)
        self.twa_map = {}
        self.system_risk_root_threats = []
        self.json_support = {}
        self.recommendations_obj = None
        logger.info("Part A calculating model risk")
        self.existing_risk_vector = None
        self.stats = {}
        self.identified_assets = defaultdict(int)
        self.cs_dict = defaultdict(ControlSet)
        self.csg_dict = defaultdict(ControlStrategy)
        self.cs_undo_list = []
        self.applied_csgs = []

    def print_stats(self):
        if self.stats:
            for k, v in self.stats.items():
                logger.debug(f"Stats: op {k} -> {v} in sec")

            apply_cs_list = [self.stats[x]['apply_cs'] for x in self.stats.keys() if x.startswith('CSG_')]
            if apply_cs_list:
                logger.debug(f"Mean apply CS time {statistics.mean(apply_cs_list)} sec")
            fetch_risk_list = [self.stats[x]['fetch_risk'] for x in self.stats.keys() if x.startswith('CSG_')]
            if fetch_risk_list:
                logger.debug(f"Mean fetch risk time {statistics.mean(fetch_risk_list)} sec")
            report_list = [self.stats[x]['compose_report'] for x in self.stats.keys() if x.startswith('CSG_')]
            if report_list:
                logger.debug(f"Mean reporting time {statistics.mean(report_list)} sec")
            undo_cs_list = [self.stats[x]['undo_cs'] for x in self.stats.keys() if x.startswith('CSG_')]
            if undo_cs_list:
                logger.debug(f"Mean undo CS time {statistics.mean(undo_cs_list)} sec")
            total_list = [self.stats[x]['total'] for x in self.stats.keys() if x.startswith('CSG_')]
            if total_list:
                logger.debug(f"Mean time for CSG {statistics.mean(total_list)} sec")

            logger.debug("Recommended CSGs")
            for rec in self.recommendations_obj.recommendations:
                logger.debug(f"Recommendation({rec.recommendation_id}) CSG: {rec.control_strategies}")

    def prepare(self):
        logger.debug("Preparing alrorithm data ...")
        if not self.existing_risk_vector:
            self.existing_risk_vector = self.get_risk_vector()
        #self.find_root_threats()
        self.populate_assets_map()

        self.json_support["existing_risk"] = self.existing_risk_vector.overall_level()
        self.json_support["existing_risk_vector"] = self.existing_risk_vector.dict()
        self.json_support["recommendations"] = []

        # initialise ObjectRecommendations
        self.recommendations_obj = ObjectRecommendation(
                existing_risk = self.existing_risk_vector.overall_level(),
                existing_risk_vector = self.existing_risk_vector,
                recommendations = [])

    def get_recommendations_obj(self):
        logger.debug("Get the recommendation response object")
        return self.recommendations_obj

    def get_risk_vector(self, mode='CURRENT'):
        logger.debug("calculate existing risk level")
        rv = self.ssm_client.calculate_runtime_risk_vector(self.model_id, mode)
        return rv

    def get_risk_vector_full(self):
        logger.debug("calculate existing risk level full")
        rv = self.ssm_client.calculate_runtime_risk_vector_full(self.model_id, 'CURRENT')
        risk_response = State(**rv)
        self.existing_risk_vector = risk_response.risk_vector
        return risk_response

    def populate_assets_map(self):
        logger.debug("populate assets map")
        assets = self.ssm_client.get_model_assets(self.model_id)
        logger.debug(f"assets found {len(assets)}")
        for asset in assets:
            self.assets_map[asset.id] = asset
        if len(self.assets_map) != len(assets):
            logger.warn(f"Assets list {len(assets)} not the same with assets map {len(self.assets_map)}")

    def get_asset_label_type(self, asset_id):
        return (self.assets_map[asset_id].label, self.assets_map[asset_id].type[67:])

    def restore_model_controls(self, overall, proposed):
        """ Restrore model control set changes """

        logger.debug("restoring model control set changes")
        self.ssm_client.undo_controls(proposed, self.model_id)
        self.ssm_client.undo_controls(overall, self.model_id)

    def enable_control_strategy(self, csg):
        """ Enable CSG by applying CS"""

        logger.info(f"enable CSG CS changes for {csg.label}")

        proposed_control_changes = []

        for cs in csg.control_sets.values():
            if cs:
                logger.debug(f"applying CS change for {cs.label}, {cs.id}, {cs.uri[67:]}")
                cs.proposed = True
                self.ssm_client.update_control_for_asset(self.model_id, cs.asset_id, cs)
                proposed_control_changes.append(cs)
                logger.debug(f"control activated for: {cs.label}")
            else:
                logger.debug(f"skipping CS change for an empty CS")

        logger.info(f"applied proposed CS changes: {len(proposed_control_changes)}")

        return proposed_control_changes

    def create_asset_record(self, control):
        """ Get asset data for recommendation"""

        logger.info(f"get asset entry for control: {control.label}")

        asset_label, asset_type = self.get_asset_label_type(control.asset_id)

        rec_entry = {
                "asset_label": asset_label,
                "asset_type": asset_type,
                "control_label": control.label,
                "uri": control.asset_uri[67:]
                }

        metadata = self.ssm_client.get_asset_metadata(control.asset_id, self.model_id)
        if metadata:
            identifier = {}
            for entry in metadata:
                identifier[entry.key] = entry.value
            if identifier:
                rec_entry['identifier'] = identifier

        logger.debug(f"asset entry for {control.label}: {rec_entry}")
        return rec_entry

    def get_recommendation_actions(self, proposed_control_changes):
        logger.info(f"get recommendation actions for {len(proposed_control_changes)} CS applied")

        actions = []

        for control in proposed_control_changes:
            rec_entry = self.create_asset_record(control)
            actions.append({"control": control.uri[67:], "control_asset": rec_entry})

        return copy.deepcopy(actions)

    def calculate_csg_recommendation(self, csg_keys, recommendation_id, category, undo_ctrl=True):
        """ Apply CSG by enabling CS, check risk and undo changes """

        my_stats = {}
        actions = []
        p_c_c = []
        control_strategies = []

        # enable control strategy
        p_0 = time.perf_counter()
        for csg_key in csg_keys:
            csg = self.csg_dict[csg_key]
            logger.info(f"Applying CSG changes for {csg.label}/{len(csg_keys)}, recommendation id: {recommendation_id}")
            control_strategies.append(csg_key)
            proposed_control_changes = self.enable_control_strategy(csg)
            p_c_c.extend(proposed_control_changes)
            actions.extend(self.get_recommendation_actions(proposed_control_changes))
        p_apply_cs = time.perf_counter()
        my_stats['apply_cs'] = round(p_apply_cs - p_0, 3)

        # calculate full model risk
        try:
            rv = self.ssm_client.calculate_runtime_risk_vector_full(self.model_id, 'CURRENT')
            risk_response = State(**rv)
            json_response = jsonable_encoder(risk_response)
            logger.debug(f"risk_calculation: {json.dumps(json_response, indent=4, sort_keys=False)}")
        except Exception as ex:
            # getting risk vector failed, restore model
            logger.warn(f"riskvector failed, {ex}, raise exception to restore model")
            # restore model
            self.restore_model_controls(proposed_control_changes, [])
            raise Exception("Failed to calculate risk model in recommendations")
        p_1a = time.perf_counter()
        my_stats["fetch_risk"] = round(p_1a - p_apply_cs, 3)
        logger.debug(f"STATS FETCHING RISK for recommendation {recommendation_id} complete in {my_stats['fetch_risk']} sec")

        # check if applied CSG reduces risk
        if self.existing_risk_vector > risk_response.risk_vector:
            logger.info("Risk recuction is observed for this strategy when " +
                        f"{len(proposed_control_changes)} CS applied")

            # populate recommendation object
            recommendation = Recommendation(
                    recommendation_id = recommendation_id,
                    category = category,
                    control_strategies = control_strategies,
                    action = actions,
                    expected_risk = risk_response.risk_vector.overall_level(),
                    expected_risk_vector = risk_response.risk_vector,
                    expected_misbehaviours = risk_response.risks)

            #logger.debug(f"recommendation {recommendation_id}: {recommendation}")
        else:
            logger.info("No risk improvement is observed for this strategy when " +
                        f"{len(proposed_control_changes)} CS applied, skipping recommendation")
            recommendation = None

        p_1c = time.perf_counter()
        my_stats["compose_report"] = round(p_1c - p_1a, 3)

        # decide to undo changes or cache
        # undo, changes, recommendation, action
        #  0      0            0           X
        #  0      0            1         not possible
        #  0      1            0         undo
        #  0      1            1         cache
        #  1      0            0           X
        #  1      0            1         not possible
        #  1      1            0         undo
        #  1      1            1         undo

        if not undo_ctrl and proposed_control_changes and recommendation:
            logger.warn("Cache proposed control changes")
            self.cs_undo_list.extend(proposed_control_changes)
        elif proposed_control_changes:
            logger.debug(f"deactivate {len(proposed_control_changes)} proposed control changes")
            self.ssm_client.undo_controls_fast(proposed_control_changes, self.model_id)
            logger.warn("Remember model is changed, model risk is now invalid")
        else:
            logger.debug("nothing to do")

        # record stats
        p_1 = time.perf_counter()
        logger.debug(f"STATS APPLYING CSG for recommendation {recommendation_id} complete in {p_1 - p_0} sec")
        my_stats["undo_cs"] = round(p_1 - p_1c, 3)
        my_stats["total"] = round(p_1 - p_0, 3)
        self.stats["CSG_"+str(recommendation_id)] = my_stats

        return recommendation


    def reset_indecies(self, clear_csg=True):
        logger.debug(f"Resetting indecies")
        self.cs_dict.clear()
        self.classified_csgs.clear()
        if clear_csg:
            self.csg_dict.clear()

    def is_csg_activated(self, csg):
        """ Check CSG is activated or not """

        activated_flag = True
        for cs in csg.control_sets.values():
            if not cs.proposed:
                activated_flag = False
                break

        return activated_flag

    def classify_threat_csg(self, threat):
        # classify Threat CSGs
        csg_classified = defaultdict(list)

        csg_dict = {}
        for csg in list(threat.control_strategies.values()):
            csg_key = csg.uri[67:]
            if not csg_key in self.csg_dict:
                csg_dict[csg_key] = csg
            else:
                logger.debug(f"Skipping cached CSG {csg_key}")

        for csg in csg_dict.values():
            csg_key = csg.uri[67:]
            short_csg_key = "CSG-" + csg_key.split("-CSG-")[1]

            # skip non IRT/RT csgs
            if not csg.uri.endswith(("-Implementation", "-Runtime")):
                logger.debug(f"\tSkipping CSG {short_csg_key}")
                for cs in csg.control_sets.values():
                    logger.debug(f"\t    └─> CP CS: {cs.label}, proposed: {cs.proposed}")
                continue

            self.csg_dict[csg_key] = csg

            logger.debug(f"\tMatching CSG {short_csg_key}")
            for cs in csg.control_sets.values():
                logger.debug(f"\t    └─> CP CS: {cs.label}, proposed: {cs.proposed}")

            # Check CSG ending in:
            #  - PatchingAtProcess-Implementation --> Conditional
            #  - Implementation                   --> Conditional
            #  - Implementation-Runtime           --> Applicable
            #  - Runtime                          --> Applicable
            if csg_key.endswith("PatchingAtProcess-Implementation"):

                if not self.is_csg_activated(csg):
                    self.classified_csgs['Conditional'].append(csg_key)
                    logger.debug(f"\t  adding {short_csg_key} to Conditional bin")
                else:
                    logger.debug(f"\t   reject {short_csg_key}, since CP is not activated")

            elif csg_key.endswith('-Implementation'):
                csg_cp_key = csg_key[:-15]
                short_csg_cp_key = "CSG-" + csg_cp_key.split("-CSG-")[1]
                if csg_cp_key in csg_dict:
                    logger.debug(f"\t  found corresponding CP: {short_csg_cp_key} id: {csg_dict[csg_cp_key].id}")
                    logger.debug(f"\t  CP CSG enabled flag: {csg_dict[csg_cp_key].enabled}")
                    if self.is_csg_activated(csg_dict[csg_cp_key]):  # already ACTIVATED
                        self.classified_csgs['Conditional'].append(csg_key)
                        logger.debug(f"\t  adding {short_csg_key} to Conditional bin")
                    else:  #NOT ACTIVATED
                        logger.debug(f"\t   reject {short_csg_key}, since CP is not activated")
                else:
                    #TODO need to check another condition, e.g. CVSS temporal metric
                    logger.warn(f"\tNo corresponding CP found, rejecting {short_csg_key}")

            elif csg_key.endswith('-Implementation-Runtime'):
                csg_cp_key = csg_key[:-23]
                short_csg_cp_key = "CSG-" + csg_cp_key.split("-CSG-")[1]
                if csg_cp_key in csg_dict:
                    logger.debug(f"\t  found corresponding CP: {short_csg_cp_key} id: {csg_dict[csg_cp_key].id}")
                    logger.debug(f"\t  CP CSG enabled flag: {csg_dict[csg_cp_key].enabled}")
                    if self.is_csg_activated(csg_dict[csg_cp_key]):  # already ACTIVATED
                        self.classified_csgs['Applicable'].append(csg_key)
                        logger.debug(f"\t  adding {short_csg_key} to Applicable bin, matching CP activated")
                else:
                    logger.warn(f"\tNo corresponding CP found, rejecting {short_csg_key}")

            elif csg_key.endswith('-Runtime'):
                self.classified_csgs['Applicable'].append(csg_key)
                logger.debug(f"\t  adding {short_csg_key} to Applicable bin")

            else:
                logger.debug(f"\tNo matching ending found, skipping {short_csg_key}, id {csg.id}")


    #def identify_threats(self, threats):
    #    """ Identify model threats that contain CSGs ending in
    #        -Implementation or -Runtime """
    #
    #    self.threats = defaultdict(Threat)
    #    for threat in threats:
    #        threat_key = threat.uri[67:]
    #        for csg in list(threat.control_strategies.values()):
    #            if csg.uri.endswith(("-Implementation", "-Runtime")):
    #                self.threat_dict[threat_key] = threat
    #                break

    def filter_misbehaviours(self, misbehaviour_sets, rlc, llc):
        """ Find misbehaviours that exceed a certain risk level of concern,
            identified misbehaviours are then, further filtered on likelihood """

        ts_2a_start = time.perf_counter()

        filtered_risk_misb = filter(lambda misb: misb.risk_level.value >= rlc.value, misbehaviour_sets)
        filtered_like_misb = filter(lambda misb: misb.likelihood.value >= llc.value, filtered_risk_misb)

        ms_dict = {}
        for misb in filtered_like_misb:
            ms_dict[misb.uri[67:]] = misb

        logger.debug(f"Identified MS of level {rlc.name}: {len(ms_dict)}")
        #logger.debug(f"MS_LIKELIHOOD: {len(ms_dict)}, {[x.likelihood.value for x in list(ms_dict.values())]}")

        ts_2a_end = time.perf_counter()
        logger.debug(f"iteration stats: identifying misbehaviours: {ts_2a_end - ts_2a_start} sec")

        return ms_dict


    def algorithm_ms(self):
        logger.debug("########## START ALGORITHM misbehaviour #############")
        logger.debug("find misbehaviours -> associated threats -> root threats -> CSGs")

        recommendation_id = 1

        # STEP1 get full model
        logger.debug("STEP1 get full model")
        p_0 = time.perf_counter()
        model = self.ssm_client.get_full_model(self.model_id)
        p_0a = time.perf_counter()
        self.stats["fetch_full_model"] = round((p_0a - p_0), 3)

        # STEP1a identify Risk Level of Concern, aka RLC
        m_rlc = RiskLevelEnum[model.risk.uri[76:]]
        m_rlc = RiskLevelEnum['Low'] # TODO RLC is manually set to LOW for debugging
        #m_rlc = RiskLevelEnum['Medium'] # TODO RLC is manually set to LOW for debugging

        # STEP2 iterate over RLC
        while m_rlc.value >= RiskLevelEnum.Low.value:
            logger.debug(f"Algorithm iteration for Risk Level of Concern: {m_rlc.name}")

            #####################
            self.reset_indecies(clear_csg=False)
            intra_recommendations = []

            # STEP2a filter for MS at the risk level of concern, likelihood
            logger.debug("STEP2a filter for MS at the level of concern and likelihood")
            ms_dict = self.filter_misbehaviours(list(model.misbehaviour_sets.values()), m_rlc, RiskLevelEnum.Medium)

            # STEP2b find associated threats and classify their CSGs
            ts_2b_start = time.perf_counter()
            logger.debug("STEP2b find associated threats and classify their CSGs")
            threat_classified_csg = set()
            for ms in ms_dict.values():
                for threat in model.threats:  # TODO model.threats is a list convet it to set (optimisation)
                    threat_key = threat.uri[67:]
                    if threat.root_cause and(ms.uri in threat.indirect_effects) and not threat_key in threat_classified_csg:
                        logger.debug(f"ROOT CAUSE threat({threat.id}): {threat.label}")
                        self.classify_threat_csg(threat)
                        threat_classified_csg.add(threat_key)

            ts_2b_end = time.perf_counter()

            # STEP2d apply CSG testing for identified root-cause threats
            logger.debug("STEP2d apply CSG testing for identified root-cause threats")
            logger.debug(f"classified CSGs: {self.classified_csgs}")
            logger.debug(f"scanned threats: {len(threat_classified_csg)}")
            ts_2d_start = time.perf_counter()

            for csg_class, csg_keys in self.classified_csgs.items():
                logger.debug(f"Testing CSG class: {csg_class}, items: {len(csg_keys)}")
                for csg_key in csg_keys:
                    logger.debug(f"testing CSG {csg_key}")
                    rec = self.calculate_csg_recommendation([csg_key], recommendation_id, csg_class)
                    #rec = None
                    if rec:
                        logger.debug(f"Adding recommendation: {rec.expected_risk}")
                        intra_recommendations.append(rec)
                    recommendation_id += 1

            if intra_recommendations:
                logger.debug("appending recommendations for this iteration")
                intra_recommendations.sort(key=lambda x: x.expected_risk_vector, reverse=False)
                logger.debug(f"Sorted recommendations for this iteration: {[x.recommendation_id for x in intra_recommendations]}")
                self.recommendations_obj.recommendations.extend(intra_recommendations)

            ts_2d_end = time.perf_counter()

            logger.debug(f"iteration stats: identifying threats: {ts_2b_end - ts_2b_start} sec")
            logger.debug(f"iteration stats: testing CSGs: {ts_2d_end - ts_2d_start} sec")

            logger.debug("DEBUG terminating algorithm loop after first iteration!!!")
            break

            #self.ssm_client.calculate_runtime_risk_only(self.model_id, 'CURRENT')
            #model = self.ssm_client.get_full_model(self.model_id)

            #logger.debug(f"MODEL RISK: {model.risk}")
            #m_rlc = RiskLevelEnum[model.risk.uri[76:]]

            # lower risk level of concern and try a new iteration
            logger.debug(f"CSG list is empty, lowering RLC, from {m_rlc.name}")
            m_rlc = RiskLevelEnum(m_rlc.value - 1)
            logger.debug(f"Lowering RLC to: {m_rlc.name}")


        # sort recommendations to their expected risk vector
        self.recommendations_obj.recommendations.sort(key=lambda x: x.expected_risk_vector, reverse=False)

        logger.debug("Undo globally cached control sets")
        logger.debug(f"   undo list size: {len(self.cs_undo_list)}")
        if self.cs_undo_list:
            self.ssm_client.undo_controls(self.cs_undo_list, self.model_id)
            logger.warn("Remember model is changed, model risk is now invalid")

        logger.debug("recalculating model risk at the end of recommendations")
        self.ssm_client.calculate_runtime_risk(self.model_id, 'CURRENT')

        p_1 = time.perf_counter()
        self.stats["alogrithm"] = round((p_1 - p_0), 3)

        logger.debug(f"Recommendation id ordered by risk level: {[x.recommendation_id for x in self.recommendations_obj.recommendations]}")
        logger.debug(f"####### FINISH ALGORITHM MS in {p_1 - p_0} sec ######")

