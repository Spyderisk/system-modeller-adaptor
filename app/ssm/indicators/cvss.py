#!/usr/bin/python3

import re
import logging


logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

""" Experiment to drive the TELEMETRY router workflow experiments """

BaseTWAS = {
        "Extrinsic-A-TW":None,   # Availability
        "Extrinsic-AU-TW":None,  # Authentication
        "Extrinsic-C-TW":None,   # Confidentiality
        "Extrinsic-I-TW":None,   # Integrity
        "Extrinsic-M-TW":None,   # Management rights
        "Extrinsic-O-TW":None,   # Overload
        "Extrinsic-QI-TW":None,  # Query Injection
        "Extrinsic-U-TW":None,   # Local User Access
        "Extrinsic-VA-TW":None,  # Local Connection
        "Extrinsic-VL-TW":None,  # Local Shell
        "Extrinsic-VN-TW":None,  # Remote Connection
        "Extrinsic-W-TW":None,   # Malware
        "Extrinsic-XS-TW":None   # Cross-Site scripting
        }

class CVSS:

    def __init__(self, cwe_dict=None):
        self._cwe_dict = cwe_dict
        self._pattern = r"Extrinsic-(XS|QI)"

    def _parse_cwe(self, cwes, newTWALevel, tmp_TWAs):
        logging.info(f"checking CWE(s): {', '.join([cwe.value for cwe in cwes])}")
        change_xs = change_qi = False

        xs_cwes = {'CWE-79', 'CWE-80', 'CWE-85', 'CWE-87', 'CWE-352'}
        qi_cwes = {'CWE-89', 'CWE-90', 'CWE-564', 'CWE-652'}

        for cwe in cwes:
            if self._cwe_dict:
                extrinsic = self._cwe_dict.get(cwe.value[4:], {}).get('TWA', '')
                if extrinsic:
                    match = re.search(self._pattern, extrinsic)
                    if match:
                        extrinsic_type = match.group(1)
                        if extrinsic_type == "XS":
                            change_xs = True
                        elif extrinsic_type == "QI":
                            change_qi = True
            else:
                logging.warning("using a limited set of CWEs")
                if cwe.value in xs_cwes:
                    change_xs = True
                if cwe.value in qi_cwes:
                    change_qi = True

        if change_xs:
            logging.info("Cross-site scripting exploitation found")
            cause = 'xs: true'

            if "Extrinsic-XS-TW" in tmp_TWAs:
                tmp_TWAs['Extrinsic-XS-TW'] = newTWALevel
            elif "Extrinsic-SX" in tmp_TWAs:
                tmp_TWAs['Extrinsic-SX-TW'] = newTWALevel
            else:
                logging.info("No cross-site scripting exploitation found")

        if change_qi:
            logging.info("Query injection exploitation found")
            cause = 'qi: true'
            tmp_TWAs['Extrinsic-QI-TW'] = newTWALevel
        else:
            logging.info("No query injection exploitation found")

        return


class CVSS2(CVSS):
    def __init__(self, cwe_dict=None):
        super().__init__(cwe_dict)

    def _attack_complexity_v2(self, attack_complexity):
        attack_complexity_levels = {
            'L': 'Low',
            'M': 'Medium',
            'H': 'High'
        }

        new_twa_level = attack_complexity_levels.get(attack_complexity)

        if new_twa_level:
            logging.info(f"{new_twa_level} trustworthiness level found")
        else:
            logging.error(f"Complexity '{attack_complexity}' is NOT supported")

        return new_twa_level

    def _attack_vector_v2(self, attack_vector, level, tmp_TWAs):
        attack_vector_levels = {
                'A': 'VA-TW',
                'L': 'VL-TW',
                'N': 'VN-TW'
                }

        suffix = attack_vector_levels.get(attack_vector)
        if suffix:
            e_av = f"Extrinsic-{suffix}"
            tmp_TWAs[e_av] = level
        else:
            logging.info("Attack vector %s not found or supported" % attack_vector)

    def parse_cvss(self, vector, cwe_list):

        tmp_TWAs = dict(BaseTWAS)

        logging.info("parse_cvss: CVSS V2 vector: %s" % vector)

        attributes = vector.split('/')

        # 1. Access Complexity - get trustworthiness level
        ac_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('AC:')), None)
        #logging.info("Access Complexity (AC) metric value: %s" % ac_value)
        newTWALevel = self._attack_complexity_v2(ac_value)

        # 2. Access Vector
        av_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('AV:')), None)
        #logging.info("Access Vector (AV) metric value: %s" % av_value)
        self._attack_vector_v2(av_value, newTWALevel, tmp_TWAs)

        # 3. Authentication
        au_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('Au:')), None)
        #logging.info("Authentication (Au) metric value: %s" % au_value)
        if au_value == 'N':
            cause = 'cvss_au: N'
            tmp_TWAs['Extrinsic-AU-TW'] = newTWALevel

        # 4a check CWEs for causes of cross-site scripting or query injection
        if cwe_list:
            self._parse_cwe(cwe_list, newTWALevel, tmp_TWAs)
        else:
            logging.info("no CWE information found for this CVE")

        # extract impact metrics
        c_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('C:')), None)
        #logging.info("Confidentiality (C) metric value: %s" % c_value)
        i_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('I:')), None)
        #logging.info("Integrity (I) metric value: %s" % i_value)
        a_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('A:')), None)
        #logging.info("Availability (A) metric value: %s" % a_value)

        # 5. If XS or QI not found then map the CVSS base vector to C, I, A.
        logging.info("Mapping CVSS base vector to M or U or a (C, I, A) combination")
        if (tmp_TWAs.get("Extrinsic-XS-TW") is None or
            tmp_TWAs.get("Extrinsic-SX-TW") is None) and \
                    tmp_TWAs.get("Extrinsic-QI-TW") is None:

            # Special cases of CIA
            # 5a. Check if all High
            if (c_value == 'C' and i_value == 'C' and a_value == 'C'):
                logging.info("Management rights exploitation found")
                cause = 'NOT (qi or xs) AND cvss_c: C cvss_i: C cvss_a: C'
                tmp_TWAs['Extrinsic-M-TW'] = newTWALevel
            # 5b. Check if all Low
            elif (c_value == 'P' and i_value == 'P' and a_value == 'P'):
                logging.info("Local user access exploitation found")
                cause = 'NOT (qi or xs) AND cvss_c: P cvss_i: P cvss_a: P'
                tmp_TWAs['Extrinsic-U-TW'] = newTWALevel
            # 5c. Else CIA
            else:
                if c_value == 'C' or c_value == 'P':
                    logging.info("Confidentiality exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_c: C|P'
                    tmp_TWAs['Extrinsic-C-TW'] = newTWALevel

                if i_value == 'C' or i_value == 'P':
                    logging.info("Integrity exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_i: C|P'
                    tmp_TWAs['Extrinsic-I-TW'] = newTWALevel

                if a_value == 'C':
                    logging.info("Availability exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_a: C'
                    tmp_TWAs['Extrinsic-A-TW'] = newTWALevel
                elif a_value == 'P':
                    logging.info("Availability exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_a: P'

                    # May want a partial TWA reduction here
                    tmp_TWAs['Extrinsic-A-TW'] = newTWALevel
                else:
                    logging.info("No mapping between CVSS base vector and M or U or C, I, A combination found")

        logging.info("\n\n####TWA suggested changes start####")
        for key, value in tmp_TWAs.items():
            if value:
                logging.info("%s:%s" % (key, value))
        logging.info("####TWA suggested changes end####\n\n")

        return tmp_TWAs


class CVSS31(CVSS):
    def __init__(self, cwe_dict=None):
        super().__init__(cwe_dict)

    def _attack_complexity_v31(self, attack_complexity, ui_value):
        attack_complexity_levels = {
            'L': 'Low',
            'H': 'High'
        }

        new_twa_level = attack_complexity_levels.get(attack_complexity)

        if attack_complexity == 'L' and ui_value == 'R':
            new_twa_level = 'Medium'

        if new_twa_level:
            logging.info(f"{new_twa_level} trustworthiness level found")
        else:
            logging.error(f"Complexity '{attack_complexity}' is NOT supported")

        return new_twa_level

    def _attack_vector_v31(self, attack_vector, level, tmp_TWAs):
        attack_vector_levels = {
                'P': 'VA-TW',  #TODO review at some point
                'A': 'VA-TW',  #TODO VL instead?
                'L': 'VL-TW',
                'N': 'VN-TW'
                }

        suffix = attack_vector_levels.get(attack_vector)
        if suffix:
            e_av = f"Extrinsic-{suffix}"
            tmp_TWAs[e_av] = level
        else:
            logging.info("Attack vector %s not found or supported" % attack_vector)

    def parse_cvss(self, vector, cwe_list):

        tmp_TWAs = dict(BaseTWAS)

        #cvss_v31_vector = cve.metrics['cvssMetricV31'][0]['cvssData']['vectorString']
        #cwe_value = cve.weaknesses[0]['description'][0]['value']

        logging.info("parse_cvss: CVSS V31 vector: %s" % vector)

        attributes = vector.split('/')

        s_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('S:')), None)
        logging.info("Scope (S) metric value: %s" % s_value)
        if s_value == 'C':
            logging.warning("cannot parse CVSS v3.1 vector with Scope metric CHANGED")
            #TODO handle better this condition
            return

        # 1. Access Complexity - get trustworthiness level
        ac_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('AC:')), None)
        #logging.info("Attack Complexity (AC) metric value: %s" % ac_value)
        ui_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('UI:')), None)
        #logging.info("User Interaction (UI) metric value: %s" % ui_value)
        newTWALevel = self._attack_complexity_v31(ac_value, ui_value)

        # 2. Access Vector
        av_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('AV:')), None)
        #logging.info("Attack Vector (AV) metric value: %s" % av_value)
        self._attack_vector_v31(av_value, newTWALevel, tmp_TWAs)

        # 3. Privileges Requiured (H L N)
        pr_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('PR:')), None)
        #logging.info("Privileges Required (PR) metric value: %s" % pr_value)
        if pr_value == 'N':
            cause = 'cvss_pr: N'
            tmp_TWAs['Extrinsic-AU-TW'] = newTWALevel
        elif pr_value == 'L':    #TODO assuming low levels privilages req is as bad as no priv required
            cause = 'cvss_pr: L'
            tmp_TWAs['Extrinsic-AU-TW'] = newTWALevel
        elif pr_value == 'H':
            logging.info("default value covers this case")
            #cause = 'cvss_pr: H'
            #tmp_TWAs['Extrinsic-AU-TW'] = newTWALevel

        # 4a check CWEs for causes of cross-site scripting or query injection
        if cwe_list:
            self._parse_cwe(cwe_list, newTWALevel, tmp_TWAs)
        else:
            logging.info("no CWE information found for this CVE")

        # extract impact metrics
        c_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('C:')), None)
        #logging.info("Confidentiality (C) metric value: %s" % c_value)
        i_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('I:')), None)
        #logging.info("Integrity (I) metric value: %s" % i_value)
        a_value = next((attr.split(':')[1] for attr in attributes if attr.startswith('A:')), None)
        #logging.info("Availability (A) metric value: %s" % a_value)

        # 5. If XS or QI not found then map the CVSS base vector to C, I, A.
        logging.info("Mapping CVSS base vector to M or U or a (C, I, A) combination")
        if (tmp_TWAs.get("Extrinsic-XS-TW") is None or
            tmp_TWAs.get("Extrinsic-SX-TW") is None) and \
                    tmp_TWAs.get("Extrinsic-QI-TW") is None:

            # Special cases of CIA
            # 5a. Check if all High
            if (c_value == 'H' and i_value == 'H' and a_value == 'H'):
                logging.info("Management rights exploitation found")
                cause = 'NOT (qi or xs) AND cvss_c: H cvss_i: H cvss_a: H'
                tmp_TWAs['Extrinsic-M-TW'] = newTWALevel
            # 5b. Check if all Low
            elif (c_value == 'L' and i_value == 'L' and a_value == 'L'):
                logging.info("Local user access exploitation found")
                cause = 'NOT (qi or xs) AND cvss_c: L cvss_i: L cvss_a: L'
                tmp_TWAs['Extrinsic-U-TW'] = newTWALevel
            # 5c. Else CIA
            else:
                if c_value == 'H' or c_value == 'L':
                    logging.info("Confidentiality exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_c: H|L'
                    tmp_TWAs['Extrinsic-C-TW'] = newTWALevel

                if i_value == 'H' or i_value == 'L':
                    logging.info("Integrity exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_i: H|L'
                    tmp_TWAs['Extrinsic-I-TW'] = newTWALevel

                if a_value == 'H':
                    logging.info("Availability exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_a: H'
                    tmp_TWAs['Extrinsic-A-TW'] = newTWALevel
                elif a_value == 'L':
                    logging.info("Availability exploitation found")
                    cause = 'NOT (qi or xs) AND cvss_a: L'

                    # May want a partial TWA reduction here
                    tmp_TWAs['Extrinsic-A-TW'] = newTWALevel
                else:
                    logging.info("No mapping between CVSS base vector and M or U or C, I, A combination found")

        logging.info("\n\n####TWA suggested changes start####")
        for key, value in tmp_TWAs.items():
            if value:
                logging.info("%s:%s" % (key, value))
        logging.info("####TWA suggested changes end####\n\n")

        return tmp_TWAs



if __name__ == "__main__":
    pass



