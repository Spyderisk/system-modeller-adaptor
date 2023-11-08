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
import sys
import inspect
import datetime
import time
import json
from collections import defaultdict
import re

from typing import List
from app.core.config import POLLING_DELAY_1, POLLING_DELAY_2
from app.core.config import SSM_URL, MAX_RISKS, DOMAIN_MODEL_VERSION
from app.core.config import FILTER_LOW_LEVEL_RISKS

from app.models.protego.vulnerability import CVSS, Identifier, Vulnerability
from app.models.protego.twa import TWA
from app.models.risk import RiskVector

from ssm_api_client import ApiClient
from ssm_api_client import Asset
from ssm_api_client import AssetControllerApi
from ssm_api_client import Configuration
from ssm_api_client import DomainModelControllerApi
from ssm_api_client import EntityControllerApi
from ssm_api_client import ModelControllerApi
from ssm_api_client import RelationControllerApi
from ssm_api_client import ThreatControllerApi

from ssm_api_client.models.risk_level_count import RiskLevelCount
from ssm_api_client.models.level import Level
from ssm_api_client.exceptions import ApiValueError
from ssm_api_client.exceptions import ApiException

from app.models.risk import RiskVector
from app.models.palette import Palette
from app.models.ssm.ssm_model import SSMModel
from app.models.ssm.ssm_model import SSMAsset
from app.models.ssm.ssm_model import SSMThreat
from app.models.ssm.ssm_model import SSMControlSet

from fastapi.logger import logger

class User:
    def __init__(self):
        self.token = None
        self.authenticated = False

class SSMClient():
    """ Create SSM client service """
    method_decorators = []

    def __init__(self, ssm_url=SSM_URL):
        ssm_host = ssm_url

        logger.info(f"INFO Initialising SSM host: {ssm_host}")

        configuration = Configuration(host=ssm_host)

        # Create an API client for SSM for a given configuration
        api_client = ApiClient(configuration)

        # Create instances of the API class
        self.api_model = ModelControllerApi(api_client)
        self.api_asset = AssetControllerApi(api_client)
        self.api_relation = RelationControllerApi(api_client)
        self.api_threat = ThreatControllerApi(api_client)
        self.api_domains = DomainModelControllerApi(api_client)
        self.api_entity = EntityControllerApi(api_client)

        # track twa changes
        self.twa_changes = []

        self.user = User()

    def authenticate_ssm_user(self, username, password):
        try:
            # Get authentication cookie from SSM
            requested_body = {'username': username, 'password': password}
            ssm_response = self.api_auth.auth(requested_body)
            if not ssm_response.authenticated:
                return False
            else:
                logger.debug(f"user token: {ssm_response.token}")
                logger.info(f"User: {username} has been authenticated successfully.")
                return ssm_response.token
        except ApiException as e:
            logger.error(f"Exception when calling AuthenticationApi->auth: {e}")
        return False


    # used by BasicAuth endpoint
    def is_authenticate_ssm_user(self, username, password):
        try:
            # Get authentication cookie from SSM
            requested_body = {'username': username, 'password': password}
            api_response = self.api_auth.auth(requested_body)
            if api_response.authenticated:
                self.user.authenticated = api_response.authenticated
                self.user.token = api_response.token
                logger.debug(f"user token: {self.user.token}")
                logger.info(f"User: {username} has been authenticated successfully.")
                return self.user.authenticated
        except ApiException as e:
            logger.error(f"Exception when calling AuthenticationApi->auth: {e}")
        return False

    def get_domain_twas(self, model_id):
        return self.api_entity.get_entity_domain_tw_as(model_id)

    def get_control(self, model_id, cs_uri):
        return self.api_entity.get_entity_domain_control(model_id, cs_uri)

    def get_system_csgs(self, model_id):
        return self.api_entity.get_entity_system_control_strategies(model_id)

    def get_system_controlsets(self, model_id):
        return self.api_entity.get_entity_system_control_sets(model_id)

    def get_system_misbehavioursets(self, model_id):
        return self.api_entity.get_entity_system_misbehaviour_sets(model_id)

    def update_controls(self, model_id, update_controls_request):
        return self.api_asset.update_controls(model_id, update_controls_request)

    def get_model(self, model_id: str):
        """ wrapper method to get_model """
        return self.api_model.get_model(model_id)

    def get_model_info(self, model_id: str):
        """ wrapper method to get_model_info """
        return self.api_model.get_model_info(model_id)

    def update_control_for_asset(self, model_id, asset_id, cs):
        """ wrapper method to update control for asset """
        return self.api_asset.update_control_for_asset(model_id, asset_id, cs)

    def get_threats_m(self, model):
        """ wrapper method to get model threats """
        cached = "true" # attempt to use cached threats, if available
        logger.debug(f"Calling get_threats_m: cached = {cached}")
        p1 = time.perf_counter()

        for threat in self.api_threat.get_threats(model.web_key, cached=cached):
            ssm_threat = SSMThreat(**threat.to_dict())
            model.threats["system#" + threat.uri.split('#')[1]] = ssm_threat
        p2 = time.perf_counter()
        model.stats['get_threats'] = f"{round((p2 - p1), 3)} sec"

    def get_threats(self, model_id):
        """ wrapper method to get model threats """
        cached = "true" # attempt to use cached threats, if available
        logger.debug(f"Calling get_threats: cached = {cached}");
        return self.api_threat.get_threats(model_id, cached=cached)

    def get_control_sets(self, model_id):
        """ wrapper method to get model control sets """
        logger.debug("Calling get_control_sets");
        return self.api_threat.get_control_sets(model_id)

    def get_control_sets_m(self, model_id):
        """ wrapper method to get model control sets """
        logger.debug("Calling get_control_sets_m");
        ssm_cs_dict = {}
        for cs in self.api_threat.get_control_sets(model_id).values():
            ssm_cs = SSMControlSet(**cs.to_dict())
            ssm_cs_dict[ssm_cs.uri[60:]] = ssm_cs
        return ssm_cs_dict

    def get_assets_m(self, model):
        """ wrapper method to get model assets """
        p1 = time.perf_counter()
        for asset in self.api_asset.get_assets(model.web_key):
            ssm_asset = SSMAsset(**asset.to_dict())
            model.assets["system#" + asset.uri.split('#')[1]] = ssm_asset
        p2 = time.perf_counter()
        model.stats['get_assets'] = f"{round((p2 - p1), 3)} sec"

    def get_assets(self, model_id):
        """ wrapper method to get model assets """
        return self.api_asset.get_assets(model_id)

    def _get_asset_metadata(self, model_id, asset_id):
        """ wrapper method to get asset metadata """
        return self.api_asset.get_asset_metadata(model_id, asset_id)

    def create_asset(self, asset_msg, model_id):
        #logger.debug(f"creating asset: {asset_msg['label']}")
        ret = None
        try:
            resp = self.api_asset.add_asset_to_model(model_id, asset_msg)
            ret = resp.asset
        except ApiException as ex:
            logger.error(f"failed to add asset {ex}")
        return ret

    def checkout_model(self, model_id):
        try:
            status = self.api_model.checkout_model(model_id)
            logger.debug(f"checkout model: {type(status)}, {status}")
        except ApiException as ex:
            logger.error(f"failed to get domain models {ex}")
        else:
            return status

    def checkin_model(self, model_id):
        try:
            status = self.api_model.checkin_model(model_id)
            logger.debug(f"checkin model: {type(status)}, {status}")
        except ApiException as ex:
            logger.error(f"failed to get domain models {ex}")
        else:
            return status


    def get_domains(self):
        try:
            domains = self.api_domains.get_domain_models()
            logger.debug(f"got domains: {type(domains)}, {domains}")
        except ApiException as ex:
            logger.error(f"failed to get domain models {ex}")
        return domains


    def create_model(self, model_name):
        try:
            logger.debug(f"create new SSM model {model_name}")
        except ApiException as ex:
            logger.error(f"failed to create new model {ex}")


    def create_relation(self, link_msg, model_id):
        #logger.debug(f"creating relation: from {link_msg['from']} -> {link_msg['to']}")
        try:
            resp = self.api_relation.create_relation(model_id, link_msg)
            #logger.debug(f"CREATE LINK RESPONSE: {type(resp)}, {resp}")
        except ApiException as ex:
            logger.error(f"failed to add relation {ex}")


    def get_palette(self, model_id: str):
        logger.debug("get palette")
        palette_dict = None
        try:
            palette_dict = self.api_model.get_palette(model_id)
            palette = Palette(**palette_dict)
        except ApiException as ex:
            logger.error(f"failed to get palette {ex}")
        return palette

    def get_model_relations(self, model_id: str):
        logger.debug("get model relations")
        relations = []
        try:
            relations = self.api_relation.list_model_relations(model_id)
        except ApiException as ex:
            logger.error(f"failed to get assets {ex}")
        return relations

    def get_model_assets(self, model_id: str):
        logger.debug("get model assets")
        assets = []
        try:
            assets = self.api_asset.get_assets(model_id)
        except ApiException as ex:
            logger.error(f"failed to get assets {ex}")
        return assets

    def check_model_exists(self, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.info("check model exists")
        try:
            model = self.api_model.get_model(modelId)
            assert (model is not None)
            logger.info("passed check model found OK")

            return True
        except ApiException as e:
            logger.error(f"Exception when checking model: {e}\n")
            return False


    def validate_model(self, modelId: str = None, mode:bool = False):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.info("validating model")
        try:
            # Check whether the model is validated.
            model = self.api_model.get_model(model_id)
            assert (model is not None)

            # If not, run model validation.
            if (not model.valid) or mode:
                if not model.valid:
                    logger.info("Model is not validated. Validating...")
                else:
                    logger.info("Validating model...")
                self.api_model.validate_model(model_id)
                #logger.debug(f'Validating model...')
                while self.api_model.get_validation_progress(model_id).progress < 1:
                    time.sleep(POLLING_DELAY_1)
                    logger.info(".")
                logger.info ("Completed model validation")
            else:
                logger.info("model is already validated")
            return True
        except ApiException as e:
            logger.error(f"Exception when validating model: {e}\n")
            return False

    def check_ssm(self):

        logger.debug("check ssm endpoint")
        try:
            # Check whether the model exists which will throw an exception 404
            model = self.api_model.get_model("xxxxx")

        except ApiException as ex:
            assert ex.status == 404
            ex_dict = json.loads(ex.body)
            assert ex_dict['message'] == "Invalid model"
            return True
        except AssertionError:
            return False

        return True


    def get_model_report(self, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug("Get model report")
        model = None
        try:
            # Check whether the model exists
            model = self.api_model.generate_report(model_id)
            assert (model is not None)

        except ApiException as e:
            logger.error(f"Exception when calling init_model: {e}\n")
            raise Exception("failed to get full model")
            #return

        return model


    def get_full_model(self, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug("Get full model and validate")
        model = None
        try:
            # Check whether the model exists
            model = self.api_model.get_model(model_id)
            assert (model is not None)

            # Get information for a model given its id.
            if model.loading_id:
                logger.debug(f"model is loading... {model.loading_id}")
                progress = 0.0
                while True:
                    model_progress = self.api_model.get_loading_progress(model_id, model.loading_id)
                    progress = model_progress.progress
                    #logger.debug(f"...progress {progress*100}%")
                    if progress == 1.0:
                        break
                    time.sleep(POLLING_DELAY_2)

                model = model_progress.model
                logger.info(f"model_progress message: {model_progress.message}")
                logger.info(f"model_progress status: {model_progress.status}")
                logger.info(f"model_progress error: {model_progress.error}")
                if model.risk:
                    logger.info(f"model risk {model.risk.label}")
                else:
                    logger.info(f"model risk might be void")

            logger.info("model is loaded")
            if model.valid:
                logger.info("The model has been already validated successfully.")
            else:
                logger.warn('The model is not valid.')
                return

        except ApiException as e:
            logger.error(f"Exception when calling init_model: {e}\n")
            raise Exception("failed to get full model")
            #return

        return model

    def get_model_risks(self, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug("Get model risks")
        model = None
        try:
            # Get model and risks
            model = self.api_model.get_model_and_risks(model_id)
            assert (model is not None)

            #logger.info("model is loaded")
            if not model.valid:
                logger.warn('The model is not valid.')
                return

        except ApiException as e:
            logger.error(f"Exception when calling init_model: {e}\n")
            raise Exception("failed to get model risks")

        return model


    def calculate_runtime_risk_fast(self, modelId:str = None, mode:str = "CURRENT", save:bool = False):
        ''' Calculate run-time risks and return new risk '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()

        try:
            logger.info(f"calculating runtime risk using mode:{mode}, save:{save}")
            model = self.api_model.calculate_risks_blocking(model_id, mode=mode, save=save)
            assert (model is not None)

            if model.model.risk:
                logger.info(f"risk level for {mode} mode is {model.model.risk} (fast)")
        except ApiException as e:
            logger.error(f"Exception when calling calculate risk fast: {e}\n")
            raise e

        p2 = time.perf_counter()
        logger.debug(f"calculate runtime risk fast time: {p2-p1} sec")

        return model

    def extract_risk_vector(self, model):
        """ extract risk vector from risk response """

        rv = RiskVector()
        rv_dict = defaultdict(int)

        p1 = time.perf_counter()
        for misb in model.misbehaviour_sets.values():
            if misb.risk:
                rv_dict[misb.risk] += 1

        if rv_dict:
            for level, value in rv_dict.items():
                snake_case = model.levels['riLevels'][level].label.replace(" ", "_").lower()
                #snake_case = self.camel_to_snake(level[16:])
                setattr(rv, snake_case, value)

        p2 = time.perf_counter()

        logger.debug(f"Extracted risk vector: {rv} in {round((p2-p1), 4)} sec")

        return rv

    def camel_to_snake(self, name):
        name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()

    def complexity_to_trustworthness(self, access_complexity):
        stem = f"http://it-innovation.soton.ac.uk/ontologies/" \
                f"trustworthiness/domain#TrustworthinessLevel"

        if access_complexity == 'L':
            label = 'Low'
        elif access_complexity == 'M':
            label = 'Medium'
        elif access_complexity == 'H':
            label = 'High'
        else:
            logger.error(f"Complexity {access_complexity} is NOT supported")
            return None, None

        return label, f"{stem}{label}"

    def complexity_to_trustworthness_old(self, access_complexity):
        if access_complexity == 'L':
            label = 'Low'
            # print(f'Trustworthiness level: {label}')
            uri = f"http://it-innovation.soton.ac.uk/ontologies/" \
                f"trustworthiness/domain#TrustworthinessLevelLow"
        elif access_complexity == 'M':
            label = 'Medium'
            # print(f'Trustworthiness level: {label}')
            uri = f"http://it-innovation.soton.ac.uk/ontologies/" \
                f"trustworthiness/domain#TrustworthinessLevelMedium"
        elif access_complexity == 'H':
            label = 'High'
            # print(f'Trustworthiness level: {label}')
            uri = f"http://it-innovation.soton.ac.uk/ontologies/" \
                f"trustworthiness/domain#TrustworthinessLevelHigh"
        return label, uri

    def get_level(self, uri):
        if uri == f"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelVeryLow":
            return 0
        elif uri == f"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelLow":
            return 1
        elif uri == f"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelMedium":
            return 2
        elif uri == f"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelHigh":
            return 3
        elif uri == f"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelVeryHigh":
            return 4

    def calculate_runtime_risk_only(self, modelId:str = None, mode:str = "CURRENT"):
        ''' Calculate run-time risks, no risk return '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()

        risk_uri = risk_name = None

        self.api_model.calculate_risks(model_id, mode)
        while self.api_model.get_risk_calc_progress(model_id).progress < 1:
            time.sleep(2)
        p2 = time.perf_counter()

        logger.debug(f"calculate runtime risk times: {p2-p1} sec")

        return


    def depricated_calculate_runtime_risk(self, modelId:str = None, mode:str = "CURRENT"):
        ''' Calculate run-time risks and return new risk '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()

        risk_uri = risk_name = None

        self.api_model.calculate_risks(model_id, mode)
        while self.api_model.get_risk_calc_progress(model_id).progress < 1:
            time.sleep(2)
        p2 = time.perf_counter()
        # get full model and find the new risk
        model = self.get_model_risks(model_id)
        p3 = time.perf_counter()

        if model.risk:
            risk_uri = model.risk.uri
            risk_name = model.risk.label
            logger.info(f"{mode} level of risk: {risk_name}")
        logger.debug(f"calculate runtime risk times: {p2-p1}/{p3-p1} sec")

        return (risk_uri, risk_name)

    def fetch_runtime_risk_vector(self, modelId:str = None) -> RiskVector:
        ''' Fetch run-time risk,
            note: if there is no initial risk calculation the call will fail
            after a limited number (3) of trials
        '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()

        retries = 3
        for i in range(1, retries+1):
            try:
                # get the new risk
                logger.debug(f"fetching ssm riskvector ({i}/{retries})")
                ssm_risk_vector = self.api_model.get_model_risk_vector(model_id)
            except Exception as e:
                logger.error(f"Exception when calling ssm riskvector: {e}\n")
                logger.warning(f"retrying {i/retries} failed get ssm riskvector")
                if i == retries:
                    logger.error(f"reached max number of retries {i}/{retries} to get riskvector")
                    raise Exception(f"failed task to get model riskvector: {e}\n")
                time.sleep(i)
                continue
            logger.debug(f"riskvector fetched after {i}/{retries} attempts")
            break

        p2 = time.perf_counter()

        adaptor_risk_vector = RiskVector().dict()
        for item in ssm_risk_vector:
            snake_case_risk_level = ssm_risk_vector[item].level.label.replace(" ", "_").lower()
            adaptor_risk_vector[snake_case_risk_level] = int(ssm_risk_vector[item].count)

        logger.info(f"MODEL RISK VECTOR: {adaptor_risk_vector}")
        f_time = p2 - p1
        logger.info(f"\tfetch risk vector timing: {f_time:.3f} sec")

        rv = RiskVector(**adaptor_risk_vector)
        logger.debug(f"RISK VECTOR obj: {rv}")
        return rv

    def calculate_runtime_risk_vector(self, modelId:str = None, mode:str = "CURRENT") -> RiskVector:
        ''' Calculate run-time risks and return new risk '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()

        # start risk calculation
        self.api_model.calculate_risks(model_id, mode)
        while self.api_model.get_risk_calc_progress(model_id).progress < 1:
            time.sleep(1)
        p2 = time.perf_counter()

        # fetch risk vector
        rv = self.fetch_runtime_risk_vector(model_id)

        p3 = time.perf_counter()

        logger.debug(f"calculate runtime risk times: {p2-p1}/{p3-p1} sec")

        logger.info(f"MODEL RISK VECTOR ({mode}): {rv}")
        r_time = p2 - p1
        f_time = p3 - p2
        logger.info(f"\trisk calculation timings risk: {r_time:.3f} sec, fetch risk vector: {f_time:.3f} sec")

        return rv

    def calculate_runtime_risk_vector_full(self, modelId:str = None,
            mode:str = "CURRENT", max_risks:int=MAX_RISKS, fullRisksData = True):
        ''' Calculate run-time risks and return new risk '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()
        logger.info(f"Calculating runtime full risk vector ({mode} risks)")

        risk_uri = risk_name = None

        self.api_model.calculate_risks(model_id, mode)
        while self.api_model.get_risk_calc_progress(model_id).progress < 1:
            time.sleep(1)
        p2 = time.perf_counter()
        logger.info('Run-time risk calculations finished successfully.')

        # get basic model and risks
        logger.info('Loading model and risks..')
        model = self.get_model_risks(model_id)
        logger.info('Model loaded')
        p3 = time.perf_counter()

        r_time = p2 - p1
        f_time = p3 - p2

        # Generate map of asset uri -> asset
        assets_map = self.get_model_assets_map(model)

        # Create map of asset id -> identifiers
        asset_identifiers = dict()

        logger.info('Extracting risks and risk vector..')

        #Limit number of misbehaviours (risks), if required (use -1 for no limit).
        #This is defined by MAX_RISKS env variable
        if max_risks > 0:
            logger.warn(f"max_risks = {max_risks}");

        risk = {'overall_risk_level': None, 'risks': []}

        risk_v = RiskVector().dict()

        #Get visible misbehaviour sets (list)
        misbehaviour_sets = self.get_model_misbehaviour_sets(model)

        #Sort misbehaviours by risk level (desc)
        sorted_misbehaviour_sets = self.sort_misbehaviour_sets(misbehaviour_sets)

        logger.info("Sorted misbehaviours (by risk_level, desc)")
        #for misb in sorted_misbehaviour_sets:
        #    logger.info(f"Misbehaviour: {misb.misbehaviour_label} at {misb.asset_label}: Risk level: {misb.risk_level['label']} ({misb.risk_level['value']})")

        #Select most significant misbehaviours (these are now top of the sorted list) and add to risks list
        #Build risk vector (risk_v) for ALL misbehaviours
        #if fullRisksData: logger.debug("Top misbehaviours:")

        for v in sorted_misbehaviour_sets:

            snake_case_risk_level = v.risk_level.label.replace(" ", "_").lower()
            risk_v[snake_case_risk_level] += 1

            #If we have selected "max_risks" risks to return,
            #or we are not getting full risks data,
            #skip the extraction of full misbehaviour data
            if not fullRisksData:
                continue
            elif max_risks > 0 and len(risk['risks']) >= max_risks:
                continue

            #Filter out very low level risks (may be disabled using FILTER_LOW_LEVEL_RISKS=FALSE)
            if FILTER_LOW_LEVEL_RISKS and snake_case_risk_level in ['low', 'very_low']:
                continue

            #logger.info(f"Misbehaviour: {v.misbehaviour_label} at {v.asset_label}: Risk level: {v.risk_level.label} ({v.risk_level.value})")
            #logger.debug(f"Full Misbehaviour: {v}")

            #Create risk object
            misb = {
                    "label": v.misbehaviour_label,
                    "likelihood": v.likelihood.label,
                    "impact": v.impact_level.label,
                    "description": v.description,
                    "risk": v.risk_level.label,
                    "uri": v.uri,
                    "asset": {"label": v.asset_label, "uri": "TODO"}
            }

            #Look up misbehaviour asset by its URI
            #logger.debug(f"Looking up asset {v.asset}")
            asset = assets_map[v.asset]
            #logger.debug(f"identified asset({asset.id}) {asset.label}, type: {asset.type[67:]}")

            #Get asset identifiers (used cached data in asset_identifiers, if available, to avoid multiple SSM look-ups)
            if asset.id not in asset_identifiers:
                identifiers = self.get_asset_identifier(asset.id, model_id)
                asset_identifiers[asset.id] = identifiers
            else:
                identifiers = asset_identifiers[asset.id]

            #logger.debug(f"identifiers: {identifiers}")

            if identifiers:
                misb['asset']["identifiers"] = identifiers
            else:
                misb['asset']["identifiers"] = []

            risk['risks'].append(misb)

        risk['risk_vector'] = risk_v

        if model.risk:
            risk['overall_risk_level'] = model.risk.label
        else:
            logger.info("model risk is not found, calculating overall risk through risk vector")
            overall_risk_level = RiskVector(**risk_v).overall_level()
            logger.info(f"calculated overall risk now is: {overall_risk_level}")
            if overall_risk_level:
                risk['overall_risk_level'] = overall_risk_level
            else:
                logger.error(f"Error calculating risk, consider re-run ssm risk calculation {risk}")

        p4 = time.perf_counter()
        logger.info(f"\trisk calculation timing, risk: {r_time:.3f} sec, fetch riskvector: {f_time:.3f} sec")
        logger.info(f"\t\tparsing assets: {(p4-p3):.3f} sec, overall: {(p4-p1):.3f} sec")

        return risk


    def calculate_runtime_risk_vector_full_fast(self, modelId:str=None, mode:str="CURRENT", max_risks:int=10, fullRisksData=True):
        ''' Calculate run-time risks and return new risk '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        p1 = time.perf_counter()

        fmodel = self.calculate_runtime_risk_fast(model_id, mode, False)

        p2 = time.perf_counter()
        r_time = p2 - p1
        logger.info('Run-time risk calculations have been finished successfully.')
        logger.info(f"\tfast risk calculation timing, risk: {r_time:.3f} sec")

        state = self.calculate_runtime_risk_vector_full_from_model(fmodel)
        return state

    def calculate_runtime_risk_vector_full_from_model(self, fmodel, risk_vector=None):
        state = {'risk': {}, 'consequences': []}

        p2 = time.perf_counter()

        if risk_vector:
            rv = risk_vector
        else:
            rv = self.extract_risk_vector(fmodel)

        state['risk']['components'] = rv.dict()

        risk_uri = risk_name = None

        if fmodel.model.risk:
            state['risk']['overall'] = fmodel.levels['riLevels'][fmodel.model.risk].label
        else:
            logger.info("model risk is not found, calculating overall risk through risk vector")
            if rv.overall_level():
                state['risk']['overall'] = rv.overall_level
                logger.info(f"calculated overall risk now is: {state['risk']['overall']}")
            else:
                logger.error(f"Error calculating risk, consider re-run ssm risk calculation {state}")

        misbehaviour_sets = list(fmodel.misbehaviour_sets.values())

        def sortFunc(misb):
            risk_level_value = 0
            if misb.risk:
                risk_level_value = fmodel.levels['riLevels'][misb.risk].level_value
            return risk_level_value

        #sort misbehaviours by current sort function
        #TODO filter our misk.risk null
        misbehaviour_sets.sort(key = sortFunc, reverse=True)

        p3 = time.perf_counter()
        #r_time = p2 - p1
        f_time = p3 - p2

        for misb in misbehaviour_sets:
            # filter MS risk level >= Medium
            if fmodel.levels['riLevels'][misb.risk].level_value < 2:
                break

            #Create risk object
            misb = {
                    "uri": misb.uri,
                    "label": fmodel.misbehaviours[misb.misbehaviour].label,
                    "likelihood": fmodel.levels['liLevels'][misb.likelihood].label,
                    "impact": fmodel.levels['imLevels'][misb.impact_level].label,
                    "description": fmodel.misbehaviours[misb.misbehaviour].description,
                    "risk": fmodel.levels['riLevels'][misb.risk].label,
                    "asset": misb.located_at
            }

            #misb['asset']["additional_properties"] = []

            state['consequences'].append(misb)

        p4 = time.perf_counter()
        #logger.info(f"\tfast risk calculation timing, risk: {r_time:.3f} sec, fetch risk components: {f_time:.3f} sec")
        logger.info(f"\tfast risk calculation timing, fetch risk components: {f_time:.3f} sec")
        #logger.info(f"\t\tparsing assets: {(p4-p3):.3f} sec, overall: {(p4-p1):.3f} sec")
        logger.info(f"\t\tparsing assets: {(p4-p3):.3f} sec")

        return state

    def get_model_misbehaviour_sets(self, model, include_invisible_misb = False):
        logger.info(f"Getting model misbehaviours (include_invisible_misb = {include_invisible_misb})")
        all_misbehaviour_sets = list(model.misbehaviour_sets.values())
        logger.info(f"Total misbehaviours: {len(all_misbehaviour_sets)}")
        if include_invisible_misb:
            return all_misbehaviour_sets
        else:
            #Select (filter) only visible misbehaviours
            visible_misbehaviour_sets = list(filter(lambda misb: misb.visible == True, all_misbehaviour_sets))
            logger.info(f"Visible misbehaviours: {len(visible_misbehaviour_sets)}")
            return visible_misbehaviour_sets

    def sort_misbehaviour_sets(self, misbehaviour_sets):
        #sort function to sort by risk value
        def sortFunc(misb):
            risk_level = int(misb.risk_level.value)
            #logger.debug(f"{risk_level}")
            return risk_level

        #sort misbehaviours by current sort function
        misbehaviour_sets.sort(key = sortFunc, reverse=True)
        #logger.debug(f"Sorted misbehaviour sets: {misbehaviour_sets}")
        return misbehaviour_sets

    #Create map of asset uri -> asset
    def get_model_assets_map(self, model):
        assets_map = dict()
        for asset in model.assets:
            assets_map[asset.uri] = asset
        return assets_map

    def get_asset_identifier(self, asset_id, modelId:str = None):
        """ find asset additional properties """

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        identifier = []
        metadata = self.api_asset.get_metadata_on_asset(model_id, asset_id, async_req=False)
        if metadata:
            for entry in metadata:
                identifier.append({"key": entry.key, "value": entry.value})
                #logger.debug(f"asset identifier key:{entry.key}, value:{entry.value}")
        #else:
        #    logger.debug(f"No metadata found for asset {asset_id}")

        return identifier

    def get_asset_metadata(self, asset_id:str, modelId:str = None):
        """ get asset additional properties """

        logger.debug("get_asset_metadata")

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        try:
            #logger.debug(f"calling get metadata on asset model id: {model_id}")
            logger.debug(f"calling get metadata on asset id: {asset_id}")
            metadata = self.api_asset.get_metadata_on_asset(model_id, asset_id, async_req=False)
        except ApiException as ex:
            logger.error(f"get_metadata_on_asset: {ex}")

        if metadata:
            logger.info(f"ASSET METADATA: {metadata}")
        else:
            logger.info(f"No metadata found for asset {asset_id}")
        return metadata

    def get_asset_twas(self, asset_id, modelId:str = None):
        """ get all asset TWAs """

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        twas = self.api_asset.get_asset_twas(model_id, asset_id, async_req=False)

        if twas:
            logger.info(f"Returning {len(twas)} TWAs")
        else:
            logger.debug(f"No TWAs found for asset {asset_id}")
        return twas

    def get_asset_control_sets(self, asset_id, modelId:str = None):
        """ get all asset control sets """

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        control_sets = self.api_asset.get_asset_control_sets(model_id, asset_id, async_req=False)

        if control_sets:
            logger.info(f"Returning {len(control_sets)} control sets")
        else:
            logger.debug(f"No control sets found for asset {asset_id}")
        return control_sets

    def parse_cwes(self, cves, cvss_dict, tw_level_uri, current_twas, asset_id,
            asset_label, modelId: str = None):
        ''' 4. CWEs
            extract all CWES from all CVES and check if there are weaknesses first '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        cwes = []
        for cve in cves:
            for k, v in cve.items():
                cwes += v

        #print(f'Associated CWEs: {cwes}')
        change_xs = change_qi = False
        for cwe in cwes:
            if cwe in ['CWE-79', 'CWE-80', 'CWE-85', 'CWE-87', 'CWE-352']:
                change_xs = True
            if cwe in ['CWE-89', 'CWE-90', 'CWE-564', 'CWE-652']:
                change_qi = True

        if change_xs:
            cause = 'xs: true'
            if DOMAIN_MODEL_VERSION == 5:
                self.update_twas('Extrinsic-XS', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)
            elif DOMAIN_MODEL_VERSION == 4:
                self.update_twas('Extrinsic-SX', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)
            else:
                logger.debug(f"Matching domain model version number not found, DOMAIN_MODEL_VERSION {DOMAIN_MODEL_VERSION}")
                self.update_twas('Extrinsic-XS', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)

        if change_qi:
            cause = 'qi: true'
            self.update_twas('Extrinsic-QI', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)

        # if no XS or QI found, then check the cases for CIA combinations
        if not (change_qi or change_xs):
            # 5. Special cases of CIA
            # Check if all Complete
            if (cvss_dict['C'] == 'C' and cvss_dict['I'] == 'C' and cvss_dict['A'] == 'C'):
                cause = 'NOT (qi or xs) AND cvss_c: C cvss_i: C cvss_a: C'
                self.update_twas('Extrinsic-M', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)
                        # Check if all Partial
            elif (cvss_dict['C'] == 'P' and cvss_dict['I'] == 'P' and cvss_dict['A'] == 'P'):
                cause = 'NOT (qi or xs) AND cvss_c: P cvss_i: P cvss_a: P'
                self.update_twas('Extrinsic-U', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)
            else:
                # 6. Else CIA
                if cvss_dict['C'] == 'C' or cvss_dict['C'] == 'P':
                    cause = 'NOT (qi or xs) AND cvss_c: C|P'
                    self.update_twas('Extrinsic-C', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)

                if cvss_dict['I'] == 'C' or cvss_dict['I'] == 'P':
                    cause = 'NOT (qi or xs) AND cvss_i: C|P'
                    self.update_twas('Extrinsic-I', current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)

                if cvss_dict['A'] == 'C':
                    cause = 'NOT (qi or xs) AND cvss_a: C'
                    TWA_label = 'Extrinsic-A'
                    self.update_twas(TWA_label, current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)
                elif cvss_dict['A'] == 'P':
                    cause = 'NOT (qi or xs) AND cvss_a: P'
                    TWA_label = 'Extrinsic-A'
                    self.update_twas(TWA_label, current_twas, tw_level_uri, asset_id, asset_label, cause, model_id)
                    #self.update_twas(TWA_label, current_twas, (tw_level_uri+1), asset_id, asset_label, cause, model_id)


    def update_twas(self, twa_label, twas, tw_level_uri, asset_id, asset_label, cause, modelId: str = None, track: bool = True):
        ''' update trustworthness attribute '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug(f"update TWA {twa_label} for asset: {asset_id}")
        for tw_key, tw_val in twas.items():
            if tw_key.find(twa_label) >= 0:
                # check new value is smaller than current one e.g. L < M < H
                tw_level = tw_level_uri[87:].upper()
                logger.debug(f"here {type(tw_val)}, {tw_val}")
                tw_val_level = tw_val.asserted_tw_level.uri[87:].upper()
                logger.debug(f"suggested change ({tw_level}) vs existing one ({tw_val_level})")
                #if TWALevel[tw_level] != TWALevel[tw_val_level]:
                if TWALevel[tw_level] < TWALevel[tw_val_level]:
                    # copy initial twa value
                    if track:
                        logger.debug("TWA changes are tracked")
                        self.twa_changes.append({"model_id": model_id,
                            "cause": cause,
                            "asset_id": asset_id, "asset_label": asset_label, "twa_key": tw_key,
                            "asserted_level_uri": tw_val.asserted_tw_level.uri,
                            "asserted_level_label": tw_val.asserted_tw_level.label,
                            "changed_from": tw_val_level, "changed_to": tw_level})
                    logger.debug(f"{twa_label} TWA will be changed: {tw_val_level} --> {tw_level}")
                    tw_val.asserted_tw_level.uri = tw_level_uri
                    #logger.debug(f"asset_id: {asset_id}, tw_val: {tw_val}")
                    #print(f"ACTUAL asset TWAs update to {tw_val} is DISABLED")
                    #self.api_asset.asset_twas_update(model_id, asset_id, tw_val)
                    self.api_asset.update_twas_for_asset(model_id, asset_id, tw_val)
                    # update current_twas object
                    twas[tw_key] = tw_val
                else:
                    logger.debug(f"{twa_label} TWA will NOT be changed: {tw_level} >= {tw_val_level}")

    def update_single_twas(self, twa_label, twas, tw_level_uri, asset_id, asset_label, cause, modelId: str = None):
        ''' update trustworthness attribute '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug(f"Update TWAS \"{twa_label}\" for asset: {asset_id} ({asset_label})")

        #TODO: create TWAS request containing only basic required fields
        #twas.asserted_tw_level["uri"] = tw_level_uri #KEM updated to the line below, as this causes "object does not support item assignment" error
        twas.asserted_tw_level.uri = tw_level_uri

        logger.info(f"Calling PUT asset twas on SSM...")
        updated_twas = self.api_asset.update_twas_for_asset(model_id, asset_id, twas)
        logger.info(f"Updated twas response: {updated_twas}")

    def parse_authentication(self, cvss_au, tw_level_uri, twas, asset_id, asset_label, modelId: str = None):
        '''parse authentication'''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        if cvss_au == 'N':
            cause = 'cvss_au: N'
            TWA_label = 'Extrinsic-AU'
            self.update_twas(TWA_label, twas, tw_level_uri, asset_id, asset_label, cause, model_id)

    def parse_access_vector(self, cvss_av, tw_level_uri, twas, asset_id, asset_label, modelId: str = None):
        ''' 2. Access Vector '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id


        logger.info(f"parse Access Vector {cvss_av}")
        TWA_label = None

        if cvss_av == 'L':
            cause = 'cvss_av: L'
            TWA_label = 'Extrinsic-AU'
            TWA_label = 'Extrinsic-VL'
        elif cvss_av == 'A':
            cause = 'cvss_av: A'
            TWA_label = 'Extrinsic-VA'
        elif cvss_av == 'N':
            cause = 'cvss_av: N'
            TWA_label = 'Extrinsic-VN'

        if TWA_label:
            self.update_twas(TWA_label, twas, tw_level_uri, asset_id, asset_label, cause, model_id)

    def find_ssm_asset(self, identifiers, modelId:str = None, verbose=True):
        ''' retrieve the corresponding asset in the SSM model '''

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        if verbose:
            logger.info(f'Locating asset in the system model with {identifiers}')

        # Get asset based on their meta-data.
        meta_pairs = []
        for item in identifiers:
            for key, value in item.items():
                meta_pairs.append(f'"{key}": "{value}"')

        metajson_string = f'[{{{",".join(meta_pairs)}}}]'
        logger.info(f"Calling get_assets_by_metadata for model {modelId}, query: {metajson_string}")

        assets = self.api_asset.get_assets_by_metadata(model_id, metajson_string)

        if assets:
            logger.warn(f'More than one SSM assets have been retrieved!')
            for asset in assets:
                logger.debug(f"ASSSSETTTT: {type(asset)}")
                logger.warn(f"examing asset matching: {asset.id}, {asset.label}")
                metadata = self.api_asset.get_metadata_on_asset(model_id, asset.id, async_req=False)
                meta_list = [{'key': i.key, 'value': i.value} for i in metadata]
                logger.debug(f"meta_list: {meta_list}")
                flag = False
                for identifier in identifiers:
                    if identifier not in meta_list:
                        logger.info(f"identifier {identifier} not found in metadata")
                        flag = True
                        break
                if not flag:
                    logger.info(f"asset found: {asset.id}")
                    return asset

            logger.warn("none of the identified assest match criteria")
            return None
        else:
            logger.info(f'SSM asset metadata query failed to find assets {identifiers}')
            return None

    def get_ssm_asset(self, modelId: str, **identifiers) -> str:
        """
        Gets a unique set of identifiers and returns the corresponding asset in
        the system model. The asset should be determined by a permanent, unique
        and unambiguous set of identifiers. Identifiers could include IP
        address, port numbers, asset_id in OpenVAS report (references). The type
        of asset can be another identifier. The identifiers are inserted into
        the SSM model as meta-data (<key, value> pairs). We thus don't need
        impure names, as the information can be stored and accessed directly
        from the meta-data of the asset. If an identifier in SIEM changes (e.g.,
        IP), then an update should be send to the SSM model. Binding: making
        references usable for access to resources.

        :param modelId: (string) The ID of the respective system model in SSM the
        asset should be located in.
        :param identifiers: (JSON) A list of identifiers to uniquely identify an
        asset in SSM
        :return: The asset as defined in SSM.
        """
        # TODO include selectors which can be applied directly on assets'
        #  attributes, e.g., type, name etc.
        # TODO check if the hostname identifier is stored in the metadata.
        #  If yes then Kubernetes has been configured. If not, the a legacy system
        #  might be in place, check for assets given their ip/port.
        if identifiers is None:
            return None

        if len(identifiers) == 0:
            return None

        meta_pairs = []
        for key, value in identifiers.items():
            meta_pairs.append(f'"key": "{key}", "value": "{value}"')
        metajson_string = f'[{{{",".join(meta_pairs)}}}]'
        logger.info(f"Calling get_assets_by_metadata for model {modelId}, query: {metajson_string}")
        return self.api_asset.get_assets_by_metadata(modelId, metajson_string)

    def change_tw_level(self, modelId: str, asset: Asset, tw_attribute: str, tw_level: str):
        twas = asset['trustworthinessAttributeSets']
        tw = \
            [v for k, v in twas.items() if
            v['attribute']['label'] == tw_attribute][0]
        tw['assertedTWLevel']['uri'] = \
            f'{tw["assertedTWLevel"]["uri"].rsplit("#")[0]}#TrustworthinessLevel{tw_level}'
        self.api_asset.update_twas_for_asset(modelId, asset.id, trustworthiness_assignment=tw)

    def undo_controls(self, control_changes, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        t0 = time.perf_counter()
        for control in control_changes:
            logger.debug(f"Undo controls for {control.uri}, {control}, {type(control)}")
            control.proposed = False
            self.api_asset.update_control_for_asset(model_id, control.asset_id, control)
        t = time.perf_counter() - t0
        logger.info(f"UNDO controls ({len(control_changes)}) done in {t:.3f} sec")


    def undo_controls_fast(self, control_changes, modelId: str = None):
        """ use this method with new API, control_changes is now a dict not an
            object
        """

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        uris = [x['cs'].uri for x in control_changes]
        logger.debug(f"UNDO controls for {uris}")
        t0 = time.perf_counter()
        for control in control_changes:
            control['cs_put']['proposed'] = False
            self.api_asset.update_control_for_asset(model_id, control['asset_id'], control['cs_put'])
        t = time.perf_counter() - t0
        logger.info(f"UNDONE controls ({len(control_changes)}) done in {t:.3f} sec")

    def undo_controls_tmp(self, control_changes, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug("Display TWAs before undoing controls")
        for asset_id in set([x.asset_id for x in control_changes]):
            asset = self.api_asset.asset_info(model_id, asset_id)
            logger.debug(f"Undo control, examining asset {asset.label}, {asset_id}")
            for t_k, t_v in asset.trustworthiness_attribute_sets.items():
                level = t_v.asserted_tw_level['uri'][87:].upper()
                #logger.debug(f"{t_k[67:]} level is {level}")

        t0 = time.perf_counter()
        for control in control_changes:
            logger.debug(f"Undo controls for {control.label}")
            control.proposed = False
            self.api_asset.update_control_for_asset(model_id, control.asset_id, control)
        t = time.perf_counter() - t0
        logger.info(f"UNDO controls ({len(control_changes)}) done in {t:.3f} sec")

    def do_twas(self, modelId: str = None, twa_change = None, cause:str="", label:str="", track:bool=True):
        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug("DO TWAS")
        if track:
            logger.debug("TWA changes are tracked")
            self.twa_changes.append({"model_id": model_id,
                "cause": cause,
                "asset_id": twa_change["asset_id"], "asset_label": "Unknown label", "twa_key": twa_change["twa_uri"],
                "asserted_level_uri": twa_change["old_level"],
                "asserted_level_label": label,
                "changed_from": twa_change["old_level"], "changed_to": twa_change["new_level"]})
        logger.debug(f"{twa_change['twa_uri']} TWA will be changed: {twa_change['old_level']} --> {twa_change['new_level']}")
        twas_json = {"uri": twa_change["twa_uri"], "assertedTWLevel": {"uri": twa_change["new_level"]}}
        self.api_asset.update_twas_for_asset(model_id, twa_change["asset_id"], twas_json)

    def undo_twas(self, modelId: str = None):

        model_id = modelId
        if not model_id:
            model_id = self.model_id

        logger.debug("UNDO TWAS")
        logger.debug("get risk vector")
        self.calculate_runtime_risk_vector(model_id)

        t0 = time.perf_counter()
        tracks_size = len(self.twa_changes)
        for twa_change in self.twa_changes:
            twa_json = {"uri": twa_change["twa_key"], "assertedTWLevel": {
                "uri": twa_change["asserted_level_uri"]} }
            self.api_asset.update_twas_for_asset( twa_change["model_id"],
                    twa_change["asset_id"], twa_json)
        self.twa_changes = []
        t = time.perf_counter() - t0
        logger.info(f"UNDO twas ({tracks_size}) done in {t:.3f} sec")
        self.calculate_runtime_risk_vector(model_id)

    def undo_twas_many(self, twas: List[TWA]):

        logger.debug(f"UNDO TWAs (many), number of TWAs to change: {len(twas)}")

        t0 = time.perf_counter()
        for twa in twas:
            logger.debug(f"Undoing TWA: {twa}")
            twa_json = {
                        "uri": twa.twa_key,
                        "assertedTWLevel": {
                            "uri": twa.asserted_level_uri
                            }
                    }
            logger.debug(f"Undoing TWA: {twa_json}")
            self.api_asset.update_twas_for_asset(twa.model_id, twa.asset_id, twa_json)

        t = time.perf_counter() - t0
        logger.info(f"UNDO twas ({len(twas)}) done in {t:.3f} sec")

    def update_control_for_asset(self, model_id, asset_id, cs):
        """ wrapper method to update control for asset """
        return self.api_asset.update_control_for_asset(model_id, asset_id, cs)

from enum import IntEnum

class TWALevel(IntEnum):
    #"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#TrustworthinessLevelLow" = 1
    # use [87:]
    VERYLOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERYHIGH = 5


class RiskLevel(IntEnum):
    #"http://it-innovation.soton.ac.uk/ontologies/trustworthiness/domain#RiskLevelVeryLow"
    # use [76:]
    VERYLOW = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    VERYHIGH = 5


# define our clear function
def clear(): # for presentation purposes only
    # for windows
    if name == 'nt':
        _ = system('cls')

        # for mac and linux(here, os.name is 'posix')
    else:
        _ = system('clear')

