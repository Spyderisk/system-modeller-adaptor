#!/usr/bin/python3

import os
import json
import requests
import csv
import time
import logging
import pickle
from collections import defaultdict

import nvdlib

from app.ssm.indicators.cvss import CVSS31
from app.ssm.indicators.cvss import CVSS2
from app.core.config import CWEC

from app.models.ssm.twa import TWASChanges, TWASChangeRecord, CVE2TWAReport
from app.core.config import NIST_API_KEY

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

""" Experiment to drive the TELEMETRY router workflow experiments """

class NVDCVE:

    CVES_CACHE = ".cves_cache"

    def __init__(self, nvd_api_key=None):
        self.nvd_api_key = nvd_api_key

        if self.nvd_api_key:
            logging.info("init NVDCVE object")
        else:
            logging.info("init NVDCVE object without API KEY")

        self._cwe_dict = self._read_cwe_data(CWEC)
        self.cvss31 = CVSS31(self._cwe_dict)
        self.cvss2 = CVSS2(self._cwe_dict)
        self.records = []

    def _read_cwe_data(self, cwe_file, rowKey='ID'):
        cwe_dict = {}
        with open(cwe_file, 'r') as file:
            for row in csv.DictReader(file):
                cwe_dict[row[rowKey]] = row
        return cwe_dict

    def _fetch_cve_data(self, cve_number):
        time_delay = 6
        nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = { 'cveId': cve_number }

        headers = { 'content-type': 'application/json'}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
            time_delay = 2

        max_attempts = 5
        response = None
        for attempt in range(1, max_attempts + 1):
            try:
                logging.info(f"Attempt {attempt}/{max_attempts}: Requesting CVE data...")
                response = requests.get(nvd_base_url, timeout=120, headers=headers, params=params)
                response.raise_for_status()
                return response.json()
            except Exception as e:
                logging.error(f"request failed attempt {attempt}: {e}")
                if attempt < max_attempts:
                    logging.info("retrying to get CVE fron NVD in 6 seconds...")
                    time.sleep(time_delay)
                else:
                    logging.critical("Max retries reached. Failed to fetch CVE data.")
                    return None
        return None


    def get_cve_data(self, cve_number):
        """ Fetch CVE data from NVD database for a given CVE id """

        logging.debug("getting data for CVE: %s", cve_number)

        #cve = self._load_cve_data_json(cve_number)
        cve = self._load_cve_data_pkl(cve_number)
        if cve:
            return cve
        logging.info("CVE not cached fetching data from NVD...")

        data = self._fetch_cve_data(cve_number)
        if data:

            if 'vulnerabilities' not in data or not data['vulnerabilities']:
                raise ValueError("No vulnerabilities found in the response.")
            else:
                cve_dict = data['vulnerabilities'][0]['cve']
                cve = nvdlib.classes.CVE(cve_dict)
                self._save_cve_json(cve_dict)

            return cve

        return None

    def get_cve_data_1(self, cve_number):
        """ Fetch CVE data from NVD database for a given CVE id """

        logging.debug("getting data for CVE: %s", cve_number)

        #cve = None  # self._load_cve_data(cve_number)
        cve = self._load_cve_data_pkl(cve_number)
        if cve:
            return cve
        logging.info("CVE not cached fetching data from NVD...")

        time_delay = 6
        nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

        params = { 'cveId': cve_number }

        headers = { 'content-type': 'application/json'}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
            time_delay = 2

        try:
            response = requests.get(nvd_base_url, timeout=120, headers=headers, params=params)
            response.raise_for_status()

            data = response.json()

            if 'vulnerabilities' not in data or not data['vulnerabilities']:
                raise ValueError("No vulnerabilities found in the response.")
            else:
                cve_dict = data['vulnerabilities'][0]['cve']
                cve = nvdlib.classes.CVE(cve_dict)
                self._save_cve_json(cve_dict)

            time.sleep(time_delay)

            return cve

        except requests.exceptions.RequestException as e:
            logging.error(f"request failed fetching CVE data: {e}")
        except KeyError as key_err:
             logging.error(f"unexpected response format (missing key): {key_err}")
        except ValueError as val_err:
            logging.error(f"data validation error: {val_err}")
        except Exception as e:
            logging.error(f"an unexpected error occurred: {e}")

        return None

    def _check_cves_data(self):
        if not os.path.exists(self.CVES_CACHE):
            os.makedirs(self.CVES_CACHE)

    def _save_cve_pkl(self, cve):
        self._check_cves_data()
        filename = os.path.join(self.CVES_CACHE, f"{cve.id}.pkl")
        with open(filename, 'wb') as file:
            pickle.dump(cve, file)

    def _load_cve_data_pkl(self, cve):
        filepath = os.path.join(self.CVES_CACHE, f"{cve}.pkl")
        if os.path.exists(filepath):
            try:
                cve_obj = None
                with open(filepath, 'rb') as file:
                    cve_obj = pickle.load(file)
                return cve_obj
            except Exception as e:
                logging.error("an unexpected error occured loading CVE: %s", e)
        else:
            logging.error("path %s not found", filepath)
        return None

    def _save_cve_json(self, cve_dict):
        if cve_dict:
            self._check_cves_data()
            filename = os.path.join(self.CVES_CACHE, f"{cve_dict['id']}.json")
            with open(filename, 'w') as file:
                json.dump(cve_dict, file, indent=4)

    def _load_cve_data_json(self, cve):
        filepath = os.path.join(self.CVES_CACHE, f"{cve}.json")
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as file:
                    data = json.load(file)
                    cve_obj = nvdlib.classes.CVE(**data)
                    return cve_obj
            except json.JSONDecodeError as e:
                logging.error("Error decoding JSON: %s", e)
            except Exception as e:
                logging.error("an unexpected error occured: %s", e)
        else:
            logging.error("path %s not found", filepath)
            return None

    def get_nvd_data(self, cve_number):
        cve = self._load_cve_data_pkl(cve_number)
        if cve:
            return cve
        logging.info(f"CVE not cached fetching {cve_number} data from NVD...")

        #response = next(nvdlib.searchCVE(cveId=cve_number, key=self.nvd_api_key, delay=6))
        response = next(nvdlib.searchCVE_V2(cveId=cve_number, key=self.nvd_api_key))
        self._save_cve_pkl(response)
        return response

    def search_nvd_cves(self, keyword):
        logging.info("searching NVD database for %s CVEs" % keyword)
        for attempt in range(3):
            try:
                response = nvdlib.searchCVE_V2(keywordSearch=keyword, delay=0.6,
                                               key=self.nvd_api_key, limit=100)
                cves = list(response)
                logging.info("%d CVEs found" % len(cves))
                return cves
            except Exception as e:
                logging.warning(f"Timeout occurred, retrying {attempt + 1}/3")
                time.sleep(5)
        logging.warning("No CVEs found in the search for %s" % keyword)
        return []

    def parse_cves(self, cves, asset_name, asset_id):
        counter = 0
        out_of = len(cves)
        cve_twas = []

        logging.info("parsing %d CVEs" % out_of)

        for cve in cves:
            counter += 1
            logging.info("=================================")
            logging.info("CVE (%d/%d) %s" % (counter, out_of, cve.id))
            logging.info("=================================")
            logging.info("*CVE Score*: %s" % cve.score)

            report = CVE2TWAReport()
            report.cve_name = cve.id
            report.description = cve.descriptions[0].value
            report.cve_score = tuple(cve.score)
            report.asset_name = asset_name
            report.asset_id = asset_id

            cwe_list = cve.cwe if hasattr(cve, 'cwe') else []
            if cwe_list:
                logging.info(f"*CVE CWE*: {cwe_list}")
                report.cwe_list = [item.value for item in cwe_list]

            available_vectors = {
                    'v2vector': getattr(cve, 'v2vector', None),
                    'v31vector': getattr(cve, 'v31vector', None),
                    'v30vector': getattr(cve, 'v30vector', None),
                    }

            available_vectors = {k: v for k, v in available_vectors.items() if v is not None}
            report.cvss_list = [v for v in available_vectors.values()]

            for key, value in available_vectors.items():
                vector = None
                logging.info(f"*{cve.id} found {key}*: {value}")
                if key == "v2vector":
                    #parser = CVSS2()
                    #vector = parser.parse_cvss(value, cwe_list)
                    vector = self.cvss2.parse_cvss(value, cwe_list)
                elif key == "v31vector":
                    #parser = CVSS31()
                    #vector = parser.parse_cvss(value, cwe_list)
                    vector = self.cvss31.parse_cvss(value, cwe_list)
                else:
                    logging.warning("Unsupported CVSS vector %s" % value)
                    continue

                if vector:
                    change = TWASChangeRecord(
                            cvss_vector=value,
                            twas=vector
                            )
                    report.proposed_twas.append(change)
            self.records.append(report)

            twas_vector = None
            vector = None

            if 'v2vector' in available_vectors:
                #logging.info(f"Processing CVSS V2: {available_vectors['v2vector']}")
                vector = available_vectors['v2vector']
                twas_vector = self.cvss2.parse_cvss(vector, cwe_list)
            elif 'v31vector' in available_vectors:
                vector = available_vectors['v31vector']
                #logging.info(f"Processing CVSS V3.1: {vector}")
                twas_vector = self.cvss31.parse_cvss(vector, cwe_list)
            elif 'v30vector' in available_vectors:
                #logging.info(f"Processing CVSS V3.0: {available_vectors['v30vector']}")
                logging.warning("CVSS v3.0 is not supported")
            else:
                logging.warning("Unknown CVSS vector found")

            if twas_vector:
                twas_changes = TWASChanges(
                        cve_name=cve.id,
                        cvss_vector=vector,
                        twas=twas_vector
                        )
                cve_twas.append(twas_changes)

        logging.info("%d TWAs changes identified" % len(cve_twas))

        #self.export_records("foola")

        return cve_twas

    def export_records(self, filename):
        json_data = json.dumps([report.model_dump() for report in self.records], indent=4)
        #with open(f"{filename}.json", "w") as f:
        #    f.write(json_data)

        with open(f"{filename}.txt", 'w') as f:
            for report in self.records:
                f.write(str(report))

    def filter_twas_changes(self, twa_changes):
        unique_list = [dict(t) for t in {tuple(sorted(d.twas.items())) for d in twa_changes}]
        return unique_list

    def filter_records_by_first_vector(self, records):
        grouped_records = defaultdict(list)
        for rec in records:
            if rec.proposed_twas and rec.proposed_twas[0].cvss_vector:
                grouped_records[rec.proposed_twas[0].cvss_vector].append(rec.cve_name)
        return dict(grouped_records)

