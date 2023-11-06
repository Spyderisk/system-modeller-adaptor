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

#import logging
#logger = logging.getLogger(__name__)

from fastapi.logger import logger

MAX_THREATS = 10

URI_PREFIX = "http://it-innovation.soton.ac.uk/ontologies/trustworthiness/"

INFINITY = 99999999

# General plot options:
FUTURE_RISK = False
LIMIT_TO_SHORTEST_PATH = True  # compute the logical expressions to only include aspects relating to the nodes on the shortest paths


class RiskCalculation():
    """ runs risk calculation and returns results """

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

    def prepare_datasets_risk(self, adjust_current_risk_controls=True):
        """ prepare datasets """

        p_00 = time.perf_counter()
        logger.debug("Preparing algorithm datasets ...")

        if not self.assets_map:
            self.populate_assets_map()

        if adjust_current_risk_controls:
            # initialise controls dictionary
            p_0 = time.perf_counter()
            for cs in self.ssm_client.get_control_sets(self.model_id).values():
                self.cs_dict[cs.uri[60:]] = cs
            p_0a = time.perf_counter()
            self.stats["fetch_model_controls"] = round((p_0a - p_0), 3)

            if self.risk_mode == 'CURRENT':
                logger.debug("CURRENT mode turning on CurrentRiskControls ...")
                self.cs_changes = self.change_currentriskcontrols()
            else:
                logger.debug("FUTURE mode turning off CurrentRiskControls ...")
                self.cs_changes = self.change_currentriskcontrols(False)
        else:
            logger.info("Skip adjusting CurrentRiskControls")

        if not self.dynamic_model or self.dirty_flag:
            p_0 = time.perf_counter()
            self.existing_risk_vector = self.get_risk_vector(True)
            self.existing_state = self.get_risk_vector_full_from_model(self.dynamic_model,
                    self.existing_risk_vector)
            p_0a = time.perf_counter()
            self.stats["fetch_dynamic_model"] = round((p_0a - p_0), 3)

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

    def create_asset_record(self, control):
        """ Get asset data for recommendation"""
        logger.info(f"get asset entry for control: {control.label}")

        short_asset_uri = control.asset_uri[60:]
        asset = self.assets_map[short_asset_uri]

        rec_entry = {
                "label": asset.label,
                "type": asset.type,
                "uri": short_asset_uri,
                "identifier": control.asset_id
                }

        identifiers = self.extract_asset_identifiers(asset)
        rec_entry['additional_properties'] = identifiers

        return rec_entry


