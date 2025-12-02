#!/usr/bin/python3

import os
import datetime
import logging
import string
import random
import json
import csv
import hashlib
import requests

from collections import defaultdict
from prettytable import PrettyTable

import nvdlib

from app.ssm.ssm_client import TWALevel
from app.ssm.indicators.nvdcve import NVDCVE

from app.core.config import NIST_API_KEY

from app.models.cve.sbomcve import CVESBOM
from app.models.ssm.twa import TWASChanges

from dataclasses import dataclass, field
from typing import List, Tuple, Dict

from fastapi.logger import logger


""" Experiment to drive the TELEMETRY router workflow experiments """

@dataclass
class DryEntry:
    risk: str = None
    cves: List[str]= field(default_factory=list)
    twa_pairs: List[Tuple[str, str]] = field(default_factory=list)


class ExperimentWorkflow:

    def __init__(self, ssm):

        logger.info("Initalising ExperimentWorkflow object")

        self.ssm = ssm
        self.nvd = NVDCVE(NIST_API_KEY)
        self.trial_id = ''.join(random.choices(string.ascii_lowercase, k=5))
        self.basemodel_rv = None
        self.model_risk = None
        self.web_key = None
        logger.info(f"starting experiment {self.trial_id}...")

        self.model_report = ""

    def update_model_report_init(self):
        ds = self.model_risk.model.description
        desc = 'N/A' if ds is None else ds if len(ds) <=50 else f"{ds[:50]}..."

        self.model_report = f"# Experiment Workflow: *{self.trial_id}*\n\n" + \
                f"## Base model data\n" + \
                f"- Model name:  {self.model_risk.model.label}\n" + \
                f"- WebKey:      {self.web_key}\n" + \
                f"- Description: {desc}\n\n" + \
                "## Risk\n" + \
                f"Risk mode:  {self.model_risk.model.risk_calculation_mode}\n" + \
                f"Risk level: *{self.model_risk.model.risk[16:]}*\n" + \
                f"RiskVector: {self.basemodel_rv}\n\n"


    def update_model_report(self, a_name, a_id):
        ds = self.model_risk.model.description
        desc = 'N/A' if ds is None else ds if len(ds) <=50 else f"{ds[:50]}..."

        self.model_report = f"# Experiment Workflow: *{self.trial_id}*\n\n" + \
                f"## Base model data\n" + \
                f"- Model name:  {self.model_risk.model.label}\n" + \
                f"- WebKey:      {self.web_key}\n" + \
                f"- Description: {desc}\n\n" + \
                "## Risk\n" + \
                f"Risk mode:  {self.model_risk.model.risk_calculation_mode}\n" + \
                f"Risk level: *{self.model_risk.model.risk[16:]}*\n" + \
                f"RiskVector: {self.basemodel_rv}\n\n" + \
                f"## Target asset *{a_name}* (Id: {a_id})"

    def workflow_I(self, basemodel_id, asset_name, keyword, dry_run=False):

        """ This workflow takes as input a model asset name that should match a
        package name, it searches NIST for CVEs towards that package. The
        return list of CVEs is converted to TWAs changes for that model asset.
        """

        logger.info(f"starting experiment optimised workflow {self.trial_id}...")

        if dry_run:
            logger.debug("DRY RUN mode ON")

        ### PART I initialise workflow ###

        # 1. create session folder
        session_folder = self.create_session_folder(f"wfI_{self.trial_id}")

        # 2. caclulate initial risk
        logger.info("getting basemodel info...")
        self.model_risk = self.ssm.calculate_runtime_risk_fast(basemodel_id)
        basemodel_name = self.model_risk.model.label
        logger.info("basemodel name: %s" % basemodel_name)
        self.basemodel_rv = self.ssm.extract_risk_vector(self.model_risk)
        logger.info("basemodel RiskVector: %s" % self.basemodel_rv)

        # 3. get asset ID
        asset_id = self.ssm.get_asset_id(asset_name, basemodel_id)
        logger.debug(f"asset {asset_name} has ASSET ID {asset_id}")

        self.update_model_report(asset_name, asset_id)

        if not asset_id:
            logger.warning("ASSET ID cannot be identified for asset name %s. Exiting workflow." % asset_name)
            self.delete_session_folder(session_folder)
            return

        logger.info("asset name '%s' corresponds to ASSET ID: %s" % (asset_name, asset_id))


        ### PART II search NIST NVD for CVEs ###
        cves = self.nvd.search_nvd_cves(keyword)

        if not cves:
            logger.warning("No CVEs found related to %s. Exiting workflow" % asset_name)
            return

        logger.info(f"{len(cves)} vulnerabilites found that could affect asset")


        ### PART III parse CVEs metrics and generate suggested TWA changes
        twas_changes = self.nvd.parse_cves(cves, asset_name, asset_id)

        if not twas_changes:
            logger.warning("No applicable CVEs found after parsing. Exiting workflow.")
            return

        logger.info(f"{len(cves)} CVEs could be applied in this system model")

        self.nvd.export_records(os.path.join(session_folder, f"vulnerabilities_{self.trial_id}"))


        ### PART IV get asset TWAs ###
        ref_twas = self.ssm.get_asset_twas(asset_id, basemodel_id)
        ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}


        ### PART V evaluate TWA changes ###
        dry_run_cache, dry_run_stats = self.evaluate_twas_changes(twas_changes, ref_twas_aux_map)


        ### PART VI apply TWA changes ###
        if not dry_run:
            self.exec_run(dry_run_cache, basemodel_id, asset_id)


        ### PART VII export results ###
        report_filename = os.path.join(session_folder, f"summary_{asset_name}")
        self.report_results(dry_run_cache, dry_run_stats, asset_name, report_filename)

        return

    def parse_security_cves(self, cve_file):
        products_to_cves = defaultdict(list)
        with open(cve_file, "r") as file:
            logging.info(f"parsing security CVE list {cve_file}")
            data = csv.DictReader(file)
            for entry in data:
                cleaned_entry = {k.strip(): v.strip() for k, v in entry.items()}
                key = cleaned_entry['cve_number']
                #self.openwrt_security_cves[key] = ProductCVE(**cleaned_entry)
                products_to_cves[cleaned_entry['product']].append(key)

        return products_to_cves

    def product_to_cves(self, sbomlist):
        sbom_cves = sbomlist.parse_cve_sbomlist()
        products_to_cves = defaultdict(set)
        for key, value in sbom_cves.items():
            if key.startswith("CVE-"):
                products_to_cves[value.product].add(value.cve_number)
            elif key.startswith("GHSA-"):
                aliases = self.ghsa_to_cve_names(key)
                for alias in aliases:
                    logger.debug(f"GHSA alias for {alias}")
                    products_to_cves[value.product].add(alias)
            else:
                logging.debug(f"non CVE entry: {value.cve_number}")
        return products_to_cves

    def map_sbom_to_assets(self, asset_product_lookup, cves_by_product, model_id):
        logger.debug("mapping SBOM Tool CVEs to model assets")

        asset_map_set = set(asset_product_lookup.keys())
        logger.debug(f"lookup table between model assets and SBOM products has {len(asset_product_lookup)} keys")

        # reverse mapping: products -> assets
        products_asset_lookup = defaultdict(list)
        for asset, products in asset_product_lookup.items():
            for product in products:
                products_asset_lookup[product].append(asset)

        # Step II get actual system model assets
        assets = self.ssm.get_assets(model_id)
        assets_dict = {}
        for asset in assets:
            if asset.asserted:
                assets_dict[asset.label] = asset.id
        asserted = set(assets_dict.keys())

        # compare actual system assets with the lookup table assets
        logger.info("lookup assets vs asserted system model assets mismatch")
        logger.info(f"missing assets from lookup table: {asserted - asset_map_set}")
        logger.info(f"orphan assets from lookup table: {asset_map_set - asserted}")

        asset_intersection = asset_map_set.intersection(asserted)
        logger.info(f"asset intersection: {asset_intersection}")

        if not asset_intersection:
            logger.warning("Assigned assets list is empty, cannot allocate CVEs to the model")
            return None

        # Step III read SBOM Tool CVE list
        # group CVEs by product

        allocated_cves = 0
        marked_products = set()
        runs = []
        for a_name in asset_intersection:
            a2p = asset_product_lookup.get(a_name, [])

            # collect all CVEs associated with the model asset (products)
            cve_names = {cve for product in a2p for cve in cves_by_product.get(product, [])}

            if cve_names:
                allocated_cves += len(cve_names)
                marked_products.update(a2p)
                runs.append({
                    "asset_name": a_name,
                    "asset_id": assets_dict.get(a_name, "Unknown"),
                    "products": a2p,
                    "cve_names": list(cve_names)
                })
                logger.info(f"ALLOCATED asset {a_name} mapped products: {a2p} with CVEs: {cve_names}")

        # Stats
        un_pkgs = 0
        un_cves = 0
        for product in set(cves_by_product.keys()) - marked_products:
            logger.debug(f"UNASSIGNED product: {product}, cves: {cves_by_product[product]}")
            un_pkgs += 1
            un_cves += len(cves_by_product[product])

        logger.info( "SBOM tool to model assets grouping summary")
        logger.info(f"Lookup table assets: {len(asset_product_lookup)}, mapped products: {len(products_asset_lookup)}")
        logger.info(f"asserted model assets: {len(asserted)}")
        logger.info(f"common assets: {len(asset_intersection)}")
        logger.info(f"SBOM tool products: {len(cves_by_product)}, vulnerabilities: len(sbom_cves)")
        logger.info(f"allocated assets: {len(runs)}, products: {len(marked_products)}, vulnerabilities: {allocated_cves}")
        logger.info(f"unassigned products: {un_pkgs}, unassigned vulnerabilities: {un_cves}")

        return runs

    def init_workflow(self, model_id):

        # 1. create session folder
        session_folder = self.create_session_folder(f"wfII_{self.trial_id}")

        # 2. caclulate initial risk
        logger.info("getting basemodel info...")
        self.model_risk = self.ssm.calculate_runtime_risk_fast(model_id)
        self.web_key = model_id
        basemodel_name = self.model_risk.model.label
        logger.info("basemodel name: %s" % basemodel_name)
        self.basemodel_rv = self.ssm.extract_risk_vector(self.model_risk)
        logger.info("basemodel RiskVector: %s" % self.basemodel_rv)

        return session_folder

    def workflow_Ia(self, basemodel_id, asset_name, assets_map_file, dry_run=False):

        logger.info(f"starting experiment Ia {self.trial_id}...")

        if dry_run:
            logger.debug("DRY RUN mode ON")

        ### PART I initialise workflow ###
        session_folder = self.init_workflow(basemodel_id)

        ### PART II map SBOM vulnerabilities to model assets
        # 3. get asset ID
        asset_id = self.ssm.get_asset_id(asset_name, basemodel_id)
        logger.debug(f"asset {asset_name} has ASSET ID {asset_id}")

        self.update_model_report(asset_name, asset_id)

        if not asset_id:
            logger.warning("ASSET ID cannot be identified for asset name %s. Exiting workflow." % asset_name)
            self.delete_session_folder(session_folder)
            return

        logger.info("asset name '%s' corresponds to ASSET ID: %s" % (asset_name, asset_id))

        # read assets mapping to packages from a file
        with open(assets_map_file, 'r') as f:
            assets_to_products = json.load(f)

        products = assets_to_products[asset_name]
        logger.debug(f"system model asset {asset_name} includes {len(products)} packages")
        logger.debug(f"packages: {products}")

        ### PART II search NIST NVD for CVEs ###
        cves = []
        for product in products:
            cves_aux = self.nvd.search_nvd_cves(product)
            cves.extend(cves_aux)

        if not cves:
            logger.warning("No CVEs found related to %s. Exiting workflow" % asset_name)
            return

        logger.info(f"{len(cves)} vulnerabilites found that could affect asset")

        ### PART III parse CVEs metrics and generate suggested TWA changes
        twas_changes = self.nvd.parse_cves(cves, asset_name, asset_id)

        if not twas_changes:
            logger.warning("No applicable CVEs found after parsing. Exiting workflow.")
            return

        logger.info(f"{len(cves)} CVEs could be applied in this system model")

        self.nvd.export_records(os.path.join(session_folder, f"vulnerabilities_{self.trial_id}"))

        ### PART IV get asset TWAs ###
        ref_twas = self.ssm.get_asset_twas(asset_id, basemodel_id)
        ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

        ### PART V evaluate TWA changes ###
        dry_run_cache, dry_run_stats = self.evaluate_twas_changes(twas_changes, ref_twas_aux_map)

        ### PART VI apply TWA changes ###
        if not dry_run:
            self.exec_run(dry_run_cache, basemodel_id, asset_id)

        ### PART VII export results ###
        report_filename = os.path.join(session_folder, f"summary_{asset_name}")
        self.report_results(dry_run_cache, dry_run_stats, asset_name, report_filename)

        return

    def workflow_multi_in_mem(self, basemodel_id, product_cves, mapping, dry_run=True):
        """ a list of CVEs is applied simultaneously to one or more assets """
        logger.info(f"starting experiment multi  {self.trial_id}...")

        asset_name = "no name"
        if dry_run:
            logger.debug("DRY RUN mode ON")

        ### PART I initialise workflow ###
        #TODO consider remobing init_workflow at least for dry runs, no need for session_folder either
        session_folder = "session_folder"  # self.init_workflow(basemodel_id)

        ### PART II map SBOM vulnerabilities to model assets

        #ma_groups = self.map_sbom_to_assets(map_file, cve_sbom_file, basemodel_id)
        ma_groups = self.map_sbom_to_assets(mapping, product_cves, basemodel_id)

        if not ma_groups:
            logger.warning("no asset mapping to vulnerable products found, exiting workflow...")
            return

        logger.debug("DEBUGGING")
        for ma_group in ma_groups:
            logger.debug(f"MA_GROUP: {ma_group}")

        multi_cache = {}
        logs = []
        for ma_group in ma_groups:

            asset_id = ma_group['asset_id']
            asset_name = ma_group['asset_name']

            log_msg = f"evaluating CVEs ({len(ma_group['cve_names'])}) for \"asset\": {asset_name}"
            logger.info(log_msg)
            logs.append(log_msg)

            records, twas_changes = self.wfx(asset_name, asset_id, ma_group['cve_names'])

            ### PART IV get asset TWAs ###
            ref_twas = self.ssm.get_asset_twas(asset_id, basemodel_id)
            ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

            ### PART V evaluate TWA changes ###
            dry_run_cache, dry_run_stats = self.evaluate_twas_changes(twas_changes, ref_twas_aux_map)

            # aggregate TWA changes
            aggregate_dry_run_cache = self._aggregate_dryrun(dry_run_cache)

            multi_cache[asset_name] = {
                    "asset_id": asset_id,
                    "runs": aggregate_dry_run_cache,
                    "stats": dry_run_stats
                    }

        ### PART VI apply multiple TWA changes ###
        new_risk = None
        if not dry_run:
            new_risk = self.exec_once_multi(basemodel_id, multi_cache)

        ### PART VII export results ###
        #report_filename = os.path.join(session_folder, "summary")
        #self.report_results_multi(multi_cache, new_risk, report_filename)

        report_dict = {}
        for asset_name, cache_data in multi_cache.items():
            dry_run, stats = cache_data['runs'], cache_data['stats']
            table = self._build_table(asset_name, dry_run)
            tot_cves, stats_msg = self._format_stats(stats)

            report_dict[asset_name] = {
                "asset_id": cache_data['asset_id'],
                "tot_cves": tot_cves,
                "stats_msg": stats_msg,
                "table": table,
                "new_risk": new_risk,
            }

        text = self._build_report_text(report_dict)


        #TODO the output should be send to DB?
        logger.info("\n".join(logs))
        return text


    def workflow_multi(self, basemodel_id, cve_sbom_file, map_file, dry_run=False):

        """ a list of CVEs is applied simultaneously to one or more assets """

        logger.info(f"starting experiment multi  {self.trial_id}...")

        asset_name = "no name"
        if dry_run:
            logger.debug("DRY RUN mode ON")

        ### PART I initialise workflow ###
        session_folder = self.init_workflow(basemodel_id)

        ### PART II map SBOM vulnerabilities to model assets

        ma_groups = self.map_sbom_to_assets(map_file, cve_sbom_file, basemodel_id)

        if not ma_groups:
            logger.warning("no asset mapping to vulnerable products found, exiting workflow...")
            return

        # update model report
        self.update_model_report_init()

        multi_cache = {}
        logs = []
        for ma_group in ma_groups:

            asset_id = ma_group['asset_id']
            asset_name = ma_group['asset_name']

            log_msg = f"evaluating CVEs ({len(ma_group['cve_names'])}) for \"asset\": {asset_name}"
            logger.info(log_msg)
            logs.append(log_msg)


            twas_changes = self.wf(asset_name, asset_id, ma_group['cve_names'], session_folder)

            ### PART IV get asset TWAs ###
            ref_twas = self.ssm.get_asset_twas(asset_id, basemodel_id)
            ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

            ### PART V evaluate TWA changes ###
            dry_run_cache, dry_run_stats = self.evaluate_twas_changes(twas_changes, ref_twas_aux_map)

            # aggregate TWA changes
            aggregate_dry_run_cache = self._aggregate_dryrun(dry_run_cache)

            multi_cache[asset_name] = {
                    "asset_id": asset_id,
                    "runs": aggregate_dry_run_cache,
                    "stats": dry_run_stats
                    }

        ### PART VI apply multiple TWA changes ###
        new_risk = None
        if not dry_run:
            new_risk = self.exec_once_multi(basemodel_id, multi_cache)

        ### PART VII export results ###
        report_filename = os.path.join(session_folder, "summary")
        self.report_results_multi(multi_cache, new_risk, report_filename)

        logger.info("\n".join(logs))
        return

    def _aggregate_dryrun(self, dry_runs):
        """ aggregate TWA updates for the same asset """

        dry_run = DryEntry()

        twa_mapping = {}   # maps left side -> chosen right side
        aggregated_cves = set()

        for dry_entry in dry_runs.values():
            aggregated_cves.update(dry_entry.cves)

            for twa_uri, twa_value in dry_entry.twa_pairs:
                current_mapping = twa_mapping.get(twa_uri)

                if current_mapping is None:
                    twa_mapping[twa_uri] = twa_value
                else:
                    if TWALevel[current_mapping.upper()] > TWALevel[twa_value.upper()]:
                        twa_mapping[twa_uri] = twa_value

        dry_run.twa_pairs = list(twa_mapping.items())
        dry_run.cves = list(aggregated_cves)

        return {"aggregate": dry_run}

    def workflow_II(self, basemodel_id, cve_sbom_file, map_file, dry_run=False):

        """ a CVE SBOB file will provide a list of CVEs along with product
        names the cve_number should be used to query NIST for that CVE, and the
        product attribute should be used to match the system model asset. For
        this last one we need to provide a mapping function, e.g. a JSON file
        that does the mapping.  """

        logger.info(f"starting experiment II  {self.trial_id}...")

        asset_name = "no name"

        if dry_run:
            logger.debug("DRY RUN mode ON")

        ### PART I initialise workflow ###
        session_folder = self.init_workflow(basemodel_id)

        ### PART II map SBOM vulnerabilities to model assets

        ma_groups = self.map_sbom_to_assets(map_file, cve_sbom_file, basemodel_id)

        if not ma_groups:
            logger.warning("no asset mapping to vulnerable products found, exiting workflow...")
            return

        logs = []
        for ma_group in ma_groups:

            asset_id = ma_group['asset_id']
            asset_name = ma_group['asset_name']

            log_msg = f"evaluating CVEs ({len(ma_group['cve_names'])}) for \"asset\": {asset_name}"
            logger.info(log_msg)
            logs.append(log_msg)

            self.update_model_report(asset_name, asset_id)

            twas_changes = self.wf(asset_name, asset_id, ma_group['cve_names'], session_folder)

            ### PART IV get asset TWAs ###
            ref_twas = self.ssm.get_asset_twas(asset_id, basemodel_id)
            ref_twas_aux_map = {twa.attribute.label: twa for twa in ref_twas.values()}

            ### PART V evaluate TWA changes ###
            dry_run_cache, dry_run_stats = self.evaluate_twas_changes(twas_changes, ref_twas_aux_map)

            ### PART VI apply TWA changes ###
            if not dry_run:
                self.exec_run(dry_run_cache, basemodel_id, asset_id)

            ### PART VII export results ###
            report_filename = os.path.join(session_folder, f"summary_{asset_name}")
            self.report_results(dry_run_cache, dry_run_stats, asset_name, report_filename)

        logger.info("\n".join(logs))
        return

    def workflow_security_cves(self, product_cves_dict):

        """ provide a dict with mappings between product and a list of CVEs """

        logger.info(f"starting experiment security cves  session id: {self.trial_id}...")

        # Step III read CVE list
        logger.debug(f"WF: there are identified {len(product_cves_dict)} products")

        products = {}
        for product, cves in product_cves_dict.items():
            records, twas = self.wfx(product, "n/a", cves)
            logger.debug(f"records, {type(records[0])}")
            products[product] = records

        return products

    def wfx(self, asset_name, asset_id, cve_names):

        logger.info(f"{len(cve_names)} CVEs found that could affect asset {asset_name}")

        cves = []
        for cve_name in cve_names:
            cve_obj = self.nvd.get_nvd_data(cve_name)
            cves.append(cve_obj)

        ### PART III parse CVEs metrics and generate suggested TWA changes
        self.nvd.records = []
        twas_changes = self.nvd.parse_cves(cves, asset_name, asset_id)

        return self.nvd.records, twas_changes

    def workflow_sbom_cves(self, cve_sbom_file):

        """ a CVE SBOB file will provide a list of CVEs along with product
        names the cve_number should be used to query NIST for that CVE, and the
        product attribute should be used to match the system model asset. For
        this last one we need to provide a mapping function, e.g. a JSON file
        that does the mapping.  """

        logger.info(f"starting experiment II  {self.trial_id}...")

        asset_name = "no name"

        # 1. create session folder
        session_folder = self.create_session_folder(f"wfII_{self.trial_id}")

        ### PART II map SBOM vulnerabilities to model assets

        # Step III read SBOM Tool CVE list
        sbom_cves = self.parse_cve_sbom_file(cve_sbom_file)
        logger.debug(f"the SBOM tool has identified {len(sbom_cves)} CVEs")

        cves_by_product = defaultdict(list)
        for cve_entry in sbom_cves:
            if cve_entry.startswith("CVE-"):
                product = sbom_cves[cve_entry].product
                cves_by_product[product].append(cve_entry)
            else:
                logger.warning(f"No CVE vulnerability found: {product}, {cve_entry}")

        for product, cves in cves_by_product.items():
            self.wf(product, "n/a", cves, session_folder)

        return

    def ghsa_to_cve_names(self, ghsa_id, timeout=10):

        """
        fetch OSV/GHSA vulnerability data.
        """

        url = f"https://api.osv.dev/v1/vulns/{ghsa_id}"

        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()   # raises HTTPError for 4xx/5xx

            try:
                data = response.json()
                return data.get("aliases", [])
            except ValueError:
                print("Error: Response was not valid JSON.")
                return None

        except requests.exceptions.Timeout:
            print("Error: Request timed out.")
            return None

        except requests.exceptions.HTTPError as e:
            print(f"HTTP error: {e}")
            return None

        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None


    def wf(self, asset_name, asset_id, cve_names, session_folder):

        logger.info(f"{len(cve_names)} CVEs found that could affect asset {asset_name}")

        cves = []
        for cve_name in cve_names:
            cve_obj = self.nvd.get_nvd_data(cve_name)
            cves.append(cve_obj)

        ### PART III parse CVEs metrics and generate suggested TWA changes
        self.nvd.records = []
        twas_changes = self.nvd.parse_cves(cves, asset_name, asset_id)

        if not twas_changes:
            logger.warning("No applicable CVEs for {asset_name} found after parsing. Exiting this asset workflow.")
            return

        logger.info(f"{len(cves)} CVEs could be applied for asset {asset_name}")

        self.nvd.export_records(os.path.join(session_folder, f"vulnerabilities_{asset_name}"))

        return twas_changes

    def evaluate_twas_changes(self,
                              twas_changes: List["TWAChange"],
                              ref_twas_aux_map: Dict[str, "TWA"]
                              ) -> Tuple[Dict[str, DryEntry], Dict[str, int]]:
        """
        Evaluate proposed TWA changes against existing asset TWAs.

        Returns:
            dry_run_cache: mapping of unique signatures to DryEntry results
            dry_run_stats: statistics about duplicates, potential changes, etc.
        """

        logger.info("Evaluating TWA changes")

        def stable_hash(obj: object) -> str:
            return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()

        # loop through suggested TWAs changes
        seen_signature: Dict[str, str] = {}
        dry_run_cache: Dict[str, DryEntry] = defaultdict(DryEntry)
        dry_run_stats: Dict[str, int] = defaultdict(int)  # {"no-impact": 0, "redundant": 0, "potential": 0}

        for twa_change in twas_changes:
            twa_signature = stable_hash(twa_change.twas)

            logger.debug(f"\n\n\nevaluating CVE:{twa_change.cve_name} signature: {twa_signature}")

            # case 1: extract duplicate
            if twa_signature in dry_run_cache:
                cve_twa_equivalent = dry_run_cache[twa_signature].cves
                logger.info(f"{twa_change.cve_name} is redundant, TWA changes have already been addressed in {cve_twa_equivalent}, skipping...")
                dry_run_cache[twa_signature].cves.append(twa_change.cve_name)
                dry_run_stats['duplicate'] += 1
                continue

            # create new entry
            dry_run_entry = DryEntry(cves=[twa_change.cve_name])

            # filter TWAs with a truthy value
            valid_twas = {k: v for k, v in twa_change.twas.items() if v}
            if not valid_twas:
                dry_run_stats['irrelevant'] += 1
                logger.warning(f"{twa_change.cve_name}: no proposed TWAs found, skipping...")
                continue

            logger.info(f"matching asset TWAs with the suggested vulnerability changes")

            for twa_key, tw_new_level in valid_twas.items():
                twa = ref_twas_aux_map.get(twa_key)
                if not twa:
                    logger.info(
                        f"Skipping suggested {twa_key}: not found in asset TWA list"
                    )
                    continue

                try:
                    if TWALevel[tw_new_level.upper()] < TWALevel[twa.asserted_tw_level.label.upper()]:
                        dry_run_entry.twa_pairs.append((twa.uri, tw_new_level))
                        logger.info(
                            f"Applicable: {twa.attribute.label} {twa.asserted_tw_level.label} --> {tw_new_level}"
                        )
                    else:
                        logger.debug(
                            f"No downgrade: keeping {twa.attribute.label} at {twa.asserted_tw_level.label}"
                        )
                except KeyError:
                    logger.error(
                        f"Invalid TWA level '{tw_new_level}' for {twa_key}, skipping."
                    )

            # Case 2: Secondary redundancy check
            if dry_run_entry.twa_pairs:
                reduced_twa_signature = stable_hash(dry_run_entry.twa_pairs)
                if reduced_twa_signature in seen_signature:
                    first_signature_key = seen_signature[reduced_twa_signature]
                    dry_run_cache[first_signature_key].cves.append(f"{twa_change.cve_name}*")
                    dry_run_stats['contained duplicate'] += 1
                    logger.info(f"secondary redundancy: {twa_change.cve_name}* skipped")
                else:
                    seen_signature[reduced_twa_signature] = twa_signature
                    dry_run_cache[twa_signature] = dry_run_entry
                    dry_run_stats['potential'] += 1
            else:
                dry_run_stats['irrelevant'] += 1
                logger.debug(f"{twa_change.cve_name} introduces no TWA changes")

        stats_msg = '\n'.join(f" - {k}: {v}" for k, v in dry_run_stats.items())
        logger.debug(f"completed TWAs chnages evaluation: \n{stats_msg}")

        return (dry_run_cache, dry_run_stats)

    def exec_once_multi(self, b_model_id, multi):
        """ Apply cumulative TWA changes for identified assets """

        logger.info(f"multiple {len(multi)} evaluations in a single risk calculation")

        logger.debug(f"copy base-model to apply vulnerabilities")
        basemodel_name = self.model_risk.model.label
        copied_model_name = f"{basemodel_name} {self.trial_id}"
        webkey = self.ssm.copy_model(b_model_id, copied_model_name)

        for asset_name, entry in multi.items():
            #if asset_name == 'kernel': continue  #TODO remove this line!!!
            asset_id = entry["asset_id"]
            erun = entry["runs"]

            for item in erun.values():
                if item.twa_pairs:
                    for twa in item.twa_pairs:
                        self.ssm.update_twas(webkey, asset_id, twa[0], twa[1])

        risk_vector = None
        risk = self.ssm.calculate_runtime_risk_fast(webkey)
        risk_vector = self.ssm.extract_risk_vector(risk)
        logger.info("modified model RiskVector: %s" % risk_vector)

        if risk_vector <= self.basemodel_rv:
            logging.debug(f"RiskVector does not get worse, deleting {copied_model_name} copy of the model")
            self.ssm.delete_model(webkey)
            logging.debug(f"{copied_model_name} model deleted")

        return risk_vector

    def exec_run(self, dry_run, b_model_id, asset_id):
        """execute risk evaluation runs separetely for each asset"""

        basemodel_name = self.model_risk.model.label
        for i, run in enumerate(dry_run.values(), 1):
            if not run.twa_pairs:
                continue
            logger.info(f"Run {i}/{len(dry_cache)} applying {run.cves}")
            copied_model_name = f"{basemodel_name} {self.trial_id} {run.cves[0]}"
            webkey = self.ssm.copy_model(b_model_id, copied_model_name)
            for twa in run.twa_pairs:
                self.ssm.update_twas(webkey, asset_id, twa[0], twa[1])
            risk = self.ssm.calculate_runtime_risk_fast(webkey)
            risk_vector = self.ssm.extract_risk_vector(risk)
            logger.info("modified model RiskVector: %s" % risk_vector)
            run.risk = str(risk_vector)

            if risk_vector <= self.basemodel_rv:
                logging.debug(f"RiskVector does not get worse, deleting {copied_model_name} copy of the model")
                self.ssm.delete_model(webkey)

    def report_results(self, dry_run, stats, asset_name="", report_filename='summary'):
        logger.info("Report run summary")

        table = PrettyTable()
        twas = f"\"{asset_name}\" TWA changes"
        table.field_names = ["Run", "CVEs", twas, "RiskVector"]
        table.align = 'l'
        table._max_width = {"CVEs": 33, twas : 23, "RiskVector": 13}

        for i, entry in enumerate(dry_run.values(), 1):
            twa_pairs = ", ".join([f"{v[0][72:-12]} -> {v[1]}" for v in entry.twa_pairs])
            table.add_row([i, ", ".join(entry.cves), twa_pairs, entry.risk or "N/A"])
        md_table = self._to_markdown_table(table)

        tot_cves = sum(v for v in stats.values())
        stats_msg = '\n'.join(f" - {k}: {v}" for k, v in stats.items())

        print(table)
        with open(f"{report_filename}.txt", 'w') as f:
            if self.model_report:
                f.write(self.model_report)
                f.write("\n\n")
            f.write(f"## Results, CVEs analysis:\n\n")
            f.write(f"Number of CVEs checked: {tot_cves}\n")
            f.write(f"{stats_msg}\n\n")
            f.write(str(table))

    def _build_table(self, asset_name, dry_run):
        table = PrettyTable()
        twas = f"\"{asset_name}\" TWA changes"
        table.field_names = ["Run", "CVEs", twas, "RiskVector"]
        table.align = 'l'
        table._max_width = {"CVEs": 33, twas: 23, "RiskVector": 13}

        for i, entry in enumerate(dry_run.values(), 1):
            twa_pairs = ", ".join([f"{v[0][72:-12]} -> {v[1]}" for v in entry.twa_pairs])
            table.add_row([i, ", ".join(entry.cves), twa_pairs, entry.risk or "N/A"])

        return table

    def _format_stats(self, stats):
        tot_cves = sum(stats.values())
        stats_msg = "\n".join(f" - {k}: {v}" for k, v in stats.items())
        return tot_cves, stats_msg

    def _build_report_text(self, report_dict):
        lines = []
        if self.model_report:
            lines.append(self.model_report)
            lines.append("")

        for asset_name, data in report_dict.items():
            lines.append(f"## Target Model Asset: {asset_name} (Id: {data['asset_id']})\n")
            lines.append(f"### Results for CVEs analysis on {asset_name}\n")
            lines.append(f"Number of CVEs checked: {data['tot_cves']}")
            lines.append(data['stats_msg'])
            lines.append(str(data['table']))
            lines.append("")

            if data['new_risk']:
                lines.append(f"New accumulative TWA changes risk vector: {data['new_risk']}\n")

        return "\n".join(lines)

    def report_results_multi(self, multi_cache, new_risk, report_filename='summary'):
        logger.info("Report multi run summary")
        if new_risk:
            logger.info(f"accumulative TWA changes risk vector: {new_risk}")

        report_dict = {}
        for asset_name, cache_data in multi_cache.items():
            dry_run, stats = cache_data['runs'], cache_data['stats']
            table = self._build_table(asset_name, dry_run)
            tot_cves, stats_msg = self._format_stats(stats)

            report_dict[asset_name] = {
                "asset_id": cache_data['asset_id'],
                "tot_cves": tot_cves,
                "stats_msg": stats_msg,
                "table": table,
                "new_risk": new_risk,
            }

            print(table)

        text = self._build_report_text(report_dict)
        with open(f"{report_filename}.txt", "w") as f:
            f.write(text)

    def _to_markdown_table(self, pt):
        _junc = pt.junction_char
        if _junc != "|":
            pt.junction_char = "|"
        markdown = [row[1:-1] for row in pt.get_string().split("\n")[1:-1]]
        pt.junction_char = _junc
        return "\n".join(markdown)

    def create_session_folder(self, stem="workflow"):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        folder_name =f"data/{stem}_{timestamp}"
        os.makedirs(folder_name, exist_ok=True)
        logging.debug("created session folder %s" % folder_name)
        return folder_name

    def delete_session_folder(self, folder_name):
        try:
            os.rmdir(folder_name)
            logging.debug("removed` session folder %s" % folder_name)
        except FileNotFoundError:
            logging.error("Session folder %s not found" % folder_name)
        except OSError:
            logging.error("Session folder %s not empty" % folder_name)


if __name__ == "__main__":
    model_id = '3bp9avsti6hfm0t2k4prc3t8je0vt4neuneb0dt5jqubis6e8vj9i9222cpqjfhip8hh8ticrbon3q7fopbafkqcitph0dohhkkak0n'

    experiment = ExperimentWorkflow(SSM_URL)

    run = experiment.workflow_1(model_id, 'uhttpd')
    experiment.print_dry_run(run)

