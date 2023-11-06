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

import re

from fastapi.encoders import jsonable_encoder

from app.models.risk import RiskLevelEnum
from app.models.protego.recommendations import Recommendation, ObjectRecommendation
from app.models.protego.recommendations import CurrentState
from app.models.risk import Risk, State
from ssm_api_client.models.control_strategy import ControlStrategy
from ssm_api_client.models.control_set import ControlSet
from ssm_api_client.models.threat_dto import ThreatDTO

from app.ssm.ssm_client import SSMClient
from app.ssm.cyberkit4sme.shortest_path import ShortestPathDataset, ThreatTree
from app.ssm.cyberkit4sme.shortest_path_graph import plot_rec_csg

from app.models.ssm.ssm_model import SSMModel
from app.models.ssm.ssm_model import SSMAsset

from fastapi.logger import logger

MAX_THREATS = 10

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"

INFINITY = 99999999

# General plot options:
FUTURE_RISK = False
LIMIT_TO_SHORTEST_PATH = True  # compute the logical expressions to only include aspects relating to the nodes on the shortest paths


class ShortestPathMitigation():
    """ Implements recommendations based on the shortest attack path tree
    threat and misbhaviour discovering. """

    def __init__(self, ssm_client, model_id, risk_mode='CURRENT'):
        self.ssm_client = ssm_client
        self.model_id = model_id
        self.risk_mode = risk_mode
        self.cs_changes = {}
        self.assets_map = {}
        self.classified_csgs = defaultdict(list)
        self.twa_map = {}
        self.system_risk_root_threats = []
        self.recommendations_obj = None
        self.recommendation_id = 1
        self.recommendation_id_phaseI = 101
        self.recommendation_plots = []
        self.existing_risk_vector = None
        self.identified_assets = defaultdict(int)
        self.threat_dict = defaultdict(ThreatDTO)
        self.cs_dict = defaultdict(ControlSet)
        self.csg_dict = defaultdict(ControlStrategy)
        self.cs_undo_list = []
        self.applied_csgs = []
        self.dynamic_model = None
        self.stats = {}
        self.rec_counter = 1
        self.threat_tree = None
        self.csg_desc = None
        self.dirty_flag = False

        # initialise internal ssm adaptor model
        self.model = SSMModel(web_key=model_id)

    def get_cs_changes(self):
        return self.cs_changes

    def print_stats(self):
        """ print recommendation stats """

        logger.debug(f"Stats summary:")
        logger.debug(f"Risk mode: {self.risk_mode}")

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

        for k, v in self.model.stats.items():
            logger.debug(f"Stats: {k} --> {v}")

            #logger.debug("Recommended CSGs")
            #for rec in self.recommendations_obj.recommendations:
            #    logger.debug(f"Recommendation({rec.identifier}) CSG: {rec.control_strategies}")

    def prepare_datasets_risk(self):
        """ prepare datasets """

        p_00 = time.perf_counter()
        logger.debug("Preparing algorithm datasets ...")

        if not self.assets_map:
            self.populate_assets_map()

        if not self.dynamic_model or self.dirty_flag:
            p_0 = time.perf_counter()
            self.existing_risk_vector = self.get_risk_vector(True)
            self.existing_state = self.get_risk_vector_full_from_model(self.dynamic_model,
                    self.existing_risk_vector)
            p_0a = time.perf_counter()
            self.stats["fetch_dynamic_model"] = round((p_0a - p_0), 3)

        p_00a = time.perf_counter()
        self.stats["prepare_datasets"] = round((p_00a - p_00), 3)


    def prepare_datasets_graph(self):
        """ prepare datasets """

        p_00 = time.perf_counter()
        logger.debug("Preparing algorithm datasets ...")

        if not self.assets_map:
            self.populate_assets_map()

        # initialise threats dictionary
        p_0 = time.perf_counter()
        for threat in self.ssm_client.get_threats(self.model_id):
            self.threat_dict[threat.uri[60:]] = threat

        #self.cs_dict = self.ssm_client.get_control_sets_m(self.model_id)

        logger.debug("LINE============================")

        if not self.dynamic_model or self.dirty_flag:
            p_0 = time.perf_counter()
            self.existing_risk_vector = self.get_risk_vector(True)
            self.existing_state = self.get_risk_vector_full_from_model(self.dynamic_model,
                    self.existing_risk_vector)
            p_0a = time.perf_counter()
            self.stats["fetch_dynamic_model"] = round((p_0a - p_0), 3)

        p_0a = time.perf_counter()
        self.stats["fetch_model_threats"] = round((p_0a - p_0), 3)

    def prepare_datasets(self):
        """ prepare datasets """

        p_00 = time.perf_counter()
        logger.debug("Preparing algorithm datasets ...")

        if not self.assets_map:
            self.populate_assets_map()

        # initialise threats dictionary
        p_0 = time.perf_counter()
        self.csg_desc = defaultdict(str)
        for threat in self.ssm_client.get_threats(self.model_id):
            self.threat_dict[threat.uri[60:]] = threat
            continue

            logger.debug(f"CSG: {type(threat.control_strategies)}, {threat.control_strategies}")

            for k, v in threat.control_strategies.items():
                logger.debug(f"CSG: {type(v)}, {v}")
                if not k[60:] in self.csg_desc:
                    self.csg_desc[k[60:]] = v
                    for k1, v1 in v.control_sets.items():
                        if not k1[60:] in self.cs_dict:
                            self.cs_dict[k1[60:]] = v1

        # intialise CSG, and CS
        mss = self.ssm_client.get_system_csgs(self.model_id)
        for k, ms in mss.items():
            self.csg_desc[k] = ms

        css = self.ssm_client.get_system_controlsets(self.model_id)
        for k, cs in css.items():
            self.cs_dict[k] = cs

        #self.cs_dict = self.ssm_client.get_control_sets_m(self.model_id)
        logger.debug(f"CS: {len(self.cs_dict)}")

        logger.debug("LINE============================")

        p_0a = time.perf_counter()
        self.stats["fetch_model_threats"] = round((p_0a - p_0), 3)
        self.stats["threats, csg, cs"] = (len(self.threat_dict), len(self.csg_desc), len(self.cs_dict))

        #TODO not sure we uset this
        # initialise controls dictionary
        p_0 = time.perf_counter()
        cs_tmp = {}
        #css = self.ssm_client.get_control_sets(self.model_id)
        for cs in self.ssm_client.get_control_sets(self.model_id).values():
            cs_tmp[cs.uri[60:]] = cs
        p_0a = time.perf_counter()
        self.stats["fetch_model_controls"] = round((p_0a - p_0), 3)
        self.stats["cs_direct"] = (len(cs_tmp))

        if not self.dynamic_model or self.dirty_flag:
            p_0 = time.perf_counter()
            self.existing_risk_vector = self.get_risk_vector(True)
            self.existing_state = self.get_risk_vector_full_from_model(self.dynamic_model,
                    self.existing_risk_vector)
            p_0a = time.perf_counter()
            self.stats["fetch_dynamic_model"] = round((p_0a - p_0), 3)

        # initialise ObjectRecommendations
        self.recommendations_obj = ObjectRecommendation(
                current=CurrentState(
                    state=State(
                        risk=Risk(
                            overall=self.existing_risk_vector.overall_level(),
                            components=self.existing_risk_vector
                            ),
                        consequences=self.existing_state.consequences
                        )
                    ),
                recommendations = []
                )

        p_00a = time.perf_counter()
        self.stats["prepare_datasets"] = round((p_00a - p_00), 3)

    def undo_currentriskcontrols(self):
        if self.cs_changes and self.cs_changes['controls']:
            p_0 = time.perf_counter()
            # reverse proposed
            mode = None
            if self.cs_changes['proposed']:
                mode = False
            else:
                mode = True
            self.cs_changes['proposed'] = mode

            if self.cs_changes:
                logger.debug(f"Undo CS changes to {self.cs_changes['proposed']}")
                self.ssm_client.update_controls(self.model_id, self.cs_changes)
                self.dirty_flag = True
                # update local cs structure
                for cs_uri in self.cs_changes['controls']:
                    self.cs_dict[cs_uri[60:]].proposed = mode
            p_1 = time.perf_counter()

            self.stats['Unset CurrentRiskCalculation controls'] = round((p_1 - p_0), 3)
        else:
            logger.debug("No CS changes to undo")

        return

    def change_currentriskcontrols(self, mode=True):
        p_0 = time.perf_counter()
        cs_crc = []
        for cs in self.cs_dict.values():
            if cs.label == "CurrentRiskCalculation":
                if cs.proposed is not mode:
                    cs_crc.append(cs.uri)

        cs_put = {'controls': cs_crc, 'proposed': mode, 'workInProgress': False}
        if cs_crc:
            self.ssm_client.update_controls(self.model_id, cs_put)
            self.dirty_flag = True
            # update local cs structure
            for cs_uri in cs_crc:
                self.cs_dict[cs_uri[60:]].proposed = mode
        p_1 = time.perf_counter()

        key = "Set CurrentRiskControls_ON"
        if not mode:
            key = "Set CurrentRiskControls_OFF"

        self.stats[key] = round((p_1 - p_0), 3)

        return cs_put

    def get_recommendations_obj(self):
        """ getter method for recommendations """
        logger.debug("Get the recommendation response object")
        return self.recommendations_obj

    def get_recommendation_plots(self):
        """ getter method for recommendation plots """
        logger.debug("Get the recommendation plots")
        return self.recommendation_plots

    def get_risk_vector(self, force=False):
        """ get risk vector using fast calculation"""
        if self.dirty_flag or force:
            self.dynamic_model = self.ssm_client.calculate_runtime_risk_fast(self.model_id, self.risk_mode)
            self.dirty_flag = False
        else:
            logger.debug(f"There is no need getting the risk vector")

        return self.ssm_client.extract_risk_vector(self.dynamic_model)

    def get_risk_vector_full(self):
        """ get risk vector using fast calculation"""

        logger.debug("get_risk_vector_full: calling calculate_runtime_risk_vector_full_fast")
        rv = self.ssm_client.calculate_runtime_risk_vector_full_fast(self.model_id, self.risk_mode)
        self.dirty_flag = False

        return self.fix_misb_asset_info(rv)

    def get_risk_vector_full_from_model(self, dynamic_model, risk_vector=None):
        """ get risk vector using existing model"""

        logger.debug("get_risk_vector_full_from_model: calling calculate_runtime_risk_vector_full_from_model")
        rv = self.ssm_client.calculate_runtime_risk_vector_full_from_model(dynamic_model, risk_vector)
        return self.fix_misb_asset_info(rv)

    def extract_asset_identifiers(self, asset):
        identifiers = []
        metadata = asset.metadata
        if metadata:
            for meta in metadata:
                identifiers.append({"key": meta.key, "value": meta.value})
        return identifiers

    def fix_misb_asset_info(self, risks):
        for risk in risks['consequences']:

            asset_uri = risk['asset']  # short uri
            try:
                asset = self.assets_map[asset_uri]
                asset_id = asset.id
                risk['asset'] = {} #initialise asset object
                risk['asset']['identifier'] = asset_id
                risk['asset']['type'] = asset.type[67:]
                risk['asset']['label'] = asset.label
                risk['asset']['uri'] = URI_PREFIX + asset_uri

                identifiers = self.extract_asset_identifiers(asset)

                risk['asset']['additional_properties'] = identifiers
            except KeyError as kerr:
                logger.debug(f"cannot find asset: {asset_uri}, {kerr}")
                risk['asset']['identifier'] = "0"
                risk['asset']['type'] = 'unknown'
            risk['uri'] = URI_PREFIX + risk['uri']

        risk_response = State(**risks)
        return risk_response

    def populate_assets_map(self):
        logger.debug("populate assets map")

        p1 = time.perf_counter()
        assets = self.ssm_client.get_model_assets(self.model_id)
        logger.debug(f"assets found {len(assets)}")

        for asset in assets:
            self.assets_map["system#" + asset.uri.split('#')[1]] = asset

        if len(self.assets_map) != len(assets):
            logger.warning(f"Assets list {len(assets)} not the same with assets map {len(self.assets_map)}")

        p2 = time.perf_counter()
        self.stats['populate_assets_map'] = round((p2 - p1), 3)

    def restore_model_controls(self, overall, proposed):
        """ Restrore model control set changes """
        logger.debug("restoring model control set changes")
        self.ssm_client.undo_controls_fast(proposed, self.model_id)
        if propossed:
            self.dirty_flag = True
        self.ssm_client.undo_controls_fast(overall, self.model_id)
        if overall:
            self.dirty_flag = True

    def create_asset_record(self, control):
        """ Get asset data for recommendation"""
        logger.info(f"get asset entry for control: {control.uri}")

        asset_uri = control.located_at
        asset = self.assets_map[asset_uri]

        rec_entry = {
                "label": asset.label,
                "type": asset.type,
                "uri": asset_uri,
                "identifier": asset.id
                }

        identifiers = self.extract_asset_identifiers(asset)
        rec_entry['additional_properties'] = identifiers

        return rec_entry

    def get_recommendation_actions(self, proposed_control_changes):
        logger.info(f"get recommendation actions for {len(proposed_control_changes)} CS applied")

        actions = []

        for control in proposed_control_changes:
            dc_uri = control['cs'].control
            dc = self.ssm_client.get_control(self.model_id, dc_uri)
            rec_entry = self.create_asset_record(control['cs'])
            label = dc.label
            label = re.sub(r'(?<!^)(?=[A-Z])', ' ', label).lower().capitalize()
            actions.append(
                    {
                        "label": label,
                        "description": dc.description,
                        "uri": control['cs'].uri,
                        "asset": rec_entry,
                        "action": "Enable control",
                        }
                    )

        return copy.deepcopy(actions)

    def filter_misbehaviours(self, misbehaviour_sets, rlc, llc):
        """ Find misbehaviours that exceed a certain risk level of concern,
            identified misbehaviours are then, further filtered on likelihood """

        ts_2a_start = time.perf_counter()

        def filter_risk_func(misb):
            if misb.risk:
                risk_level_value = self.dynamic_model.levels['riLevels'][misb.risk].level_value
                if  risk_level_value >= rlc.value:
                    return True
            return False

        def filter_prior_func(misb):
            if misb.likelihood:
                prior_level_value = self.dynamic_model.levels['liLevels'][misb.likelihood].level_value
                if prior_level_value >= llc.value:
                    return True
            return False

        #filtered_risk_misb = filter(filter_risk_func, misbehaviour_sets)
        #filtered_like_misb = filter(filter_prior_func, filtered_risk_misb)

        filtered_risk = filter(filter_risk_func, misbehaviour_sets)
        filtered = filter(filter_prior_func, filtered_risk)

        def sortFunc(misb):
            if misb.risk and misb.likelihood:
                risk_v = self.dynamic_model.levels['riLevels'][misb.risk].level_value
                prior_v = self.dynamic_model.levels['liLevels'][misb.likelihood].level_value
            return risk_v * 10 + prior_v

        ms_sorted = sorted(filtered, key=sortFunc, reverse=True)

        ms_dict = {}

        for misb in ms_sorted:
            ms_dict[misb.uri] = misb

        logger.debug(f"Filtered MS of Risk level >= {rlc.name} and Likelihood >= {llc.name}: {len(ms_dict)}")

        ts_2a_end = time.perf_counter()
        logger.debug(f"STATS: filtering misbehaviours took: {ts_2a_end - ts_2a_start} sec")

        self.stats['filter_misbehaviours'] = round((ts_2a_end - ts_2a_start), 3)
        return ms_dict

    def apply_cs_set(self, cs_set):
        proposed_control_changes = []
        for cs_uri in cs_set:
            cs = self.cs_dict[cs_uri]
            if cs:
                logger.debug(f"applying CS change for {cs_uri}")
                cs.proposed = True
                cs_put = {'uri': URI_PREFIX + cs_uri, 'proposed': True, 'workInProgress': False}
                cs_asset_id = self.assets_map[cs.located_at].id
                self.ssm_client.update_control_for_asset(self.model_id, cs_asset_id, cs_put)
                proposed_control_changes.append({'cs': cs, 'asset_id': cs_asset_id, 'cs_put': cs_put})
                logger.debug(f"control activated for: {cs_uri}")
                self.dirty_flag = True
            else:
                logger.debug(f"skipping CS change for a NONE CS")

        logger.info(f"applied proposed CS changes: {len(proposed_control_changes)}")

        return proposed_control_changes


    def lookup_cs_in_csg(self, csg_uri):
        """ find CS that need to be enabled for CSG"""

        csg = self.csg_desc[csg_uri]
        logger.info(f"enable CSG CS changes for {csg.label}")

        available_cs_uri = set()

        #for k, v in csg.control_sets.items():
        mandatory_optional =  csg.mandatory_cs + csg.optional_cs
        for cs_uri in mandatory_optional:
            if not self.cs_dict[cs_uri].proposed:
                available_cs_uri.add(cs_uri)

        return available_cs_uri

    def convert_csg_symbols(self, le_list):
        """ convert from symbol or AND() to CSG_list """
        csg_uris = []
        for le in le_list:
            if isinstance(le, Symbol):
                csg_uris.append(le.obj)
            elif isinstance(le.cause, AND):
                for symbol in option.cause.args:
                    csg_uris.append(symbol.obj)
            else:
                logger.error(f"Logical Expression operator not supported {le.cause.operator}")

        return csg_uris

    def get_list_from_and(self, logical_expression):
        """ take a logical expression and return a list of symbols
        """

        ret_val = []
        if isinstance(logical_expression, Symbol):
            ret_val = [logical_expression]
        elif isinstance(logical_expression, AND):
            for option in logical_expression.args:
                ret_val.append(option)
                logger.debug(f"convert CSG option, adding {option}")
        else:
            logger.error(f"convert_csg_options: Logical Expression operator not supported")

        return ret_val


    def apply_csgs(self, logical_expression, my_node=None):
        if not my_node:
            my_node = CSGNode()

        # convert logical expression to DNF
        logical_expression.apply_dnf()

        # convert from CSG_logical_expression to list of CSG_options
        csg_options = logical_expression.get_list_from_or()

        for csg_option in csg_options:
            logger.debug(f"examining CSG option {csg_option}")

            options = self.get_list_from_and(csg_option)

            csg_list = self.convert_csg_symbols(options)

            child_node = CSGNode(csg_list)

            my_node.add_child(child_node)

            cs_set = set()
            actual_csg_list = []
            for csg in csg_list:
                csg_uri = self.threat_tree.get_dummy_uriref(csg)
                actual_csg_list.append(csg_uri)
                logger.debug(f"CSG: {csg}, {csg_uri}")

                csg_cs_set = self.lookup_cs_in_csg(csg_uri)
                cs_set.update(csg_cs_set)
            logger.debug(f"CS set for CSG_option...")
            logger.debug(f"CS set {cs_set}")

            # apply all CS in the CS_set
            pcc = self.apply_cs_set(cs_set)
            #logger.debug(f"pcc: {[x['cs'].uri for x in pcc]}")

            # recalculate risk and create a recommendation
            try:
                risk_response = self.get_risk_vector_full()
                logger.debug(f"Risk vector: {risk_response.risk.components}")

                # populate recommendation object
                control_strategies = [{'uri': uri, 'description': self.csg_desc[uri].description} for uri in actual_csg_list]
                recommendation = Recommendation(
                        identifier=self.recommendation_id_phaseI,
                        category="unknown",
                        control_strategies=control_strategies,
                        controls=self.get_recommendation_actions(pcc),
                        state=risk_response
                        )
                child_node.recommendation = copy.deepcopy(recommendation)
                self.recommendation_id_phaseI += 1

            except Exception as ex:
                # getting risk vector failed, restore model
                logger.warn(f"riskvector failed, {ex}, raise exception to restore model")
                # restore model
                self.restore_model_controls_fast(pcc, [])
                raise Exception("Failed to calculate risk model in recommendations")

            # if risk is low enough, add CSG_list to node
            overall = risk_response.risk.overall.replace(" ", "")
            if RiskLevelEnum.Medium.value >= RiskLevelEnum[overall].value:
                logger.info("Termination condition")
            else:
                logger.info("Recalculate threat tree ... ")
                tt = self.calculate_attack_tree('low')
                nle = tt.attack_mitigation_csg
                self.apply_csgs(nle, child_node)

            # undo CS changes in CS_set
            logger.debug(f"undo CS set")
            if pcc:
                self.ssm_client.undo_controls_fast(pcc, self.model_id)
                #risk_resp = self.get_risk_vector_full()
                #logger.debug(f"Undone Risk vector: {risk_resp.risk.components}")

        logger.debug(f"return from iteration: {my_node.csg_list}")
        if not my_node.recommendation:
            logger.debug("  -->NO RECOMMENDATION")

        return my_node

    def create_first_pass_plot(self, level='', output_format:str = 'svg'):
        self.get_risk_vector()

        if level == 'low':
            ms_dict = self.filter_misbehaviours(list(self.dynamic_model.misbehaviour_sets.values()),
                    RiskLevelEnum.Low, RiskLevelEnum.Low)
        else:
            ms_dict = self.filter_misbehaviours(list(self.dynamic_model.misbehaviour_sets.values()),
                    RiskLevelEnum.Medium, RiskLevelEnum.Medium)

        #Instead of passing the full model (no longer available), create an object containing the model data
        model_data = {
            'assets': self.assets_map,
            'threats': self.threat_dict,
            'csg_sets': self.csg_desc,
            'control_sets': self.cs_dict
        }

        apd = ShortestPathDataset(self.dynamic_model, model_data)

        logger.debug(f"Identified Misbehaviours: {len(ms_dict)}")
        ms_uris = [x.uri for x in ms_dict.values()]

        # TODO passing one MS as target_uri for testing purposes
        threat_tree = ThreatTree(ms_uris, FUTURE_RISK, LIMIT_TO_SHORTEST_PATH, apd)

        logger.debug("SUMMARISING CSG options for all target misbehaviours...")
        logger.debug(f"{threat_tree.attack_mitigation_csg.pretty_print(max_complexity=600)}")
        logger.debug(f"{threat_tree.attack_mitigation_csg.pretty_print_d(max_complexity=600)}")

        threat_tree.stats()

        label = self.dynamic_model.model.label
        graph = threat_tree.parse_and_plot_tree_nodes(self.rec_counter, label, output_format)

        return graph

    def calculate_attack_tree(self, level=''):
        self.get_risk_vector()

        if level == 'low':
            ms_dict = self.filter_misbehaviours(list(self.dynamic_model.misbehaviour_sets.values()),
                    RiskLevelEnum.Low, RiskLevelEnum.Low)
        else:
            ms_dict = self.filter_misbehaviours(list(self.dynamic_model.misbehaviour_sets.values()),
                    RiskLevelEnum.Medium, RiskLevelEnum.Medium)

        #Instead of passing the full model (no longer available), create an object containing the model data
        model_data = {
            'assets': self.assets_map,
            'threats': self.threat_dict,
            'csg_sets': self.csg_desc,
            'control_sets': self.cs_dict
        }

        apd = ShortestPathDataset(self.dynamic_model, model_data)

        logger.debug(f"Identified Misbehaviours: {len(ms_dict)}")
        ms_uris = [x.uri for x in ms_dict.values()]

        threat_tree = ThreatTree(ms_uris, FUTURE_RISK, LIMIT_TO_SHORTEST_PATH, apd)

        label = self.dynamic_model.model.label
        svg_doc = threat_tree.parse_and_plot_tree_nodes(self.rec_counter, label, 'svg')
        basename = self.dynamic_model.model.label.replace(" ", "_")
        with open(f"{basename}_graph_plot_{self.rec_counter}.svg", "wb") as f:
            f.write(svg_doc)
        self.rec_counter += 1

        logger.debug("SUMMARISING CSG options for all target misbehaviours...")
        logger.debug(f"{threat_tree.attack_mitigation_csg.pretty_print(max_complexity=600)}")
        logger.debug(f"{threat_tree.attack_mitigation_csg.pretty_print_d(max_complexity=600)}")

        threat_tree.stats()

        return threat_tree


    def algorithm_shortest_path(self):
        logger.debug("########## START ALGORITHM attack path #############")
        logger.debug("find misbehaviours -> calculate attack path")

        if not self.dynamic_model:
            error_msg = "please run prepare_datasets() method before the algorithm"
            logger.error(error_msg)
            raise Exception(error_msg)

        self.threat_tree = self.calculate_attack_tree()

        attack_mitigation_csg = self.threat_tree.attack_mitigation_csg

        root_node = self.apply_csgs(attack_mitigation_csg)

        #self.existing_risk_vector = self.get_risk_vector_full().risk.components
        self.existing_risk_vector = self.get_risk_vector()
        logger.debug(f"PhaseI Risk vector: {self.existing_risk_vector}")

        logger.debug("\n\n###################################################")
        logger.debug("Explore solutions tree and make recommendations")
        logger.debug("###################################################\n\n")
        self.nodes = []
        self.links = []
        self.make_recommendations(root_node)

        basename = self.dynamic_model.model.label.replace(" ", "_")
        plot_rec_csg(basename+"_plot", self.nodes, self.links)

        return

    def short_uri(self, uri):
        """ short CSG URI """
        csg_uri = self.threat_tree.get_dummy_uriref(uri)
        return csg_uri.split("_")[-1]

    def make_recommendations(self, node, path=None):
        """ This revised method should not run more risk calculations, insttead
        it will try to attached recommendations directly from nodes """

        if not node.csg_list:
            root_csg_list = "root"
        else:
            root_csg_list = ", ".join([self.threat_tree.get_dummy_uriref(x) for x in node.csg_list])
        self.nodes.append(root_csg_list)

        if not path:
            path = []

        logger.debug(" "*len(path)*4 + f"MAKE RECOMMENDATIONS TREE: {node.csg_list}")
        if node.recommendation:
            logger.debug(" "*len(path)*4 + f"└─>CACHED RECOMMENDATION: {node.recommendation.state.risk}")
        else:
            logger.debug(" "*len(path)*4 + f"└─>NO CACHED RECOMMENDATION found!")

        path.append(node)

        if node.children:
            for child in node.children:
                self.links.append([root_csg_list, ", ".join([self.threat_tree.get_dummy_uriref(x) for x in child.csg_list])])
                self.make_recommendations(child, copy.deepcopy(path))
        else:
            csg_list = []
            for p in path:
                for i in p.csg_list:
                    csg_list.append(i)
            logger.debug(" "* len(path)*4 + f"*ADDING* CACHED path recommendation csg_list: {csg_list}")

            # add cached recommendation
            cached_rec = copy.deepcopy(node.recommendation)
            if cached_rec:
                self.recommendations_obj.recommendations.append(cached_rec)

    def parse_rec_tree(self, root):
        nodes = []
        links = []

        self.explore_tree1(root, nodes, links)

        logger.debug(f"nodes: {nodes}")
        logger.debug(f"links: {links}")

        plot_rec_csg("fp_uc1", nodes, links)

    def explore_tree1(self, root, nodes, links):
        if not root.csg_list:
            root_csg_list = "root"
        else:
            root_csg_list = "_".join(root.csg_list)
        nodes.append(root_csg_list)
        for child in root.children:
            links.append([root_csg_list, "_".join(child.csg_list)])
            self.explore_tree1(child, nodes, links)


class CSGNode:
    def __init__(self, csg_list=None):
        if csg_list is None:
            csg_list = []
        self.csg_list = csg_list
        self.children = []
        self.recommendation = None

    def add_child(self, child):
        self.children.append(child)


