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
##      Created By :            Samuel Senior
##      Created Date :          2021-05-18
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

from app.core.config import DOMAIN_MODEL_VERSION

from app.ssm.ssm_client import TWALevel

from fastapi.logger import logger

import csv

class AlertMappings:
    def __init__(self):
        pass

    def _csvToDict(self, csvFile, rowKey):
        csvDict = {}
        with open(csvFile, 'r') as file:
            for row in csv.DictReader(file):
                csvDict[row[rowKey]] = row
        return csvDict

    def readInCWEs(self, cweMappingFile_new=None):
        if cweMappingFile_new == None:
            cweMappingFile = self._cweMappingFile
        else:
            cweMappingFile = cweMappingFile_new
            self._cweMappingFile = cweMappingFile_new
            
        cweDict = self._csvToDict(cweMappingFile, "ID")
        for key in cweDict.keys():
            cweDict[key]['TWA'] = cweDict[key]['TWA'].split(",")
        return cweDict
    
    def readInWASCs(self, wascMappingFile_new=None):
        if wascMappingFile_new == None:
            wascMappingFile = self._wascMappingFile
        else:
            wascMappingFile = wascMappingFile_new
            self._wascMappingFile = wascMappingFile_new
            
        return self._csvToDict(wascMappingFile, "WASC ID")
    
    def readInCAPECs(self, capecMappingFile_new=None):
        if capecMappingFile_new == None:
            capecMappingFile = self._capecMappingFile
        else:
            capecMappingFile = capecMappingFile_new
            self._capecMappingFile = capecMappingFile_new
            
        capecDict = self._csvToDict(capecMappingFile, "ID")
        for key in capecDict.keys():
            capecDict[key]['TWA'] = capecDict[key]['TWA'].split(",")
        return capecDict
    
    def readInOWASPTop102010(self, owasp2010MappingFile_new=None):
        if owasp2010MappingFile_new == None:
            owasp2010MappingFile = self._owasp2010MappingFile
        else:
            owasp2010MappingFile = owasp2010MappingFile_new
            self._owasp2010MappingFile = owasp2010MappingFile_new
            
        owasp2010Dict = self._csvToDict(owasp2010MappingFile, "Name")
        for key in owasp2010Dict.keys():
            owasp2010Dict[key]['TWA'] = owasp2010Dict[key]['TWA'].split(",")
        return owasp2010Dict

    def _returnWorstTWAAndLevel(self, twa_1, twa_level_1, twa_2, twa_level_2):
        # If either twa_1 or twa_2 is None and therefore not an actual TWA
        if twa_1 == None:
            if twa_2 == None:
                return None, None
            else:
                return twa_2, twa_level_2
        elif twa_2 == None:
            return twa_1, twa_level_1

        # If the level of twa_1 or twa_2 is missing then either return the TWA with an actual level or default to
        # returning twa_1 (this is different to a missing TWA like above as we can approximate the missing level later
        # on, plus returning None due to a missing level doesn't make sense as we know that one of the TWAs has to be
        # affected, we're just trying to work out which one based on which one has the lowest level).
        if twa_level_1 == "??":
            if twa_level_2 == "??":
                return twa_1, twa_level_1
            else:
                return twa_2, twa_level_2
        elif twa_level_2 == "??":
            return twa_1, twa_level_1

        # Return the TWA with the lowest level, and default to twa_1 if it
        # can't be determined.
        if TWALevel[twa_level_1.upper()] < TWALevel[twa_level_2.upper()]:
            return twa_1, twa_level_1
        elif TWALevel[twa_level_2.upper()] < TWALevel[twa_level_1.upper()]:
            return twa_2, twa_level_2
        else:
            return twa_1, twa_level_1

    def _twaMappingSearch(self, mappingID:str, mapping):
        twa = None
        twa_newLevel = None

        if mappingID in mapping.keys() and mapping[mappingID]['TWA'] != ["??"]:
            twa = mapping[mappingID]['TWA']
            twa_newLevel = mapping[mappingID]['TWA New Level']

        return twa, twa_newLevel

    def _findCweTWAsAndLevel(self, cwes:str, alertid):
        # If we have TWA scope info in the CWE then we use that
        twa = None
        twa_newLevel = None
        cwes = cwes.split(",")
        for cwe in cwes:
            twa_tmp = None
            twa_newLevel_tmp = None
            if cwe != "??":
                logger.info(f"[alert {alertid}] Found TWA for mapped CWE {cwe}")
                twa_tmp, twa_newLevel_tmp = self._twaMappingSearch(cwe, self._cweMappings)
                if twa_tmp == None:
                    logger.info(f"[alert {alertid}] Unsupported CWE {cwe} missing TWA in mapping")
                    self._skippedAlerts['cweUnsupported'][alertid] = {"alertid":alertid, "cweid":cwe, "reason":f"Unsupported CWE {cwe} missing TWA in mapping"}
                else:
                    logger.info(f"[alert {alertid}] Found {twa_tmp} with level {twa_newLevel_tmp}")
            else:
                logger.info(f"[alert {alertid}] Unsupported CWE {cwe} missing TWA in CWE mapping")
                self._skippedAlerts['cweUnsupported'][alertid] = {"alertid":alertid, "cweid":cwe, "reason":f"Unsupported CWE {cwe} missing TWA in CWE mapping"}

            twa, twa_newLevel = self._returnWorstTWAAndLevel(twa, twa_newLevel, twa_tmp, twa_newLevel_tmp)

        return twa, twa_newLevel

    def _findCapecTWAsAndLevel(self, capecs:str, wascid, alertid):
        # Look inside the WASC mapping to see if there's a suitable CAPEC
        twa = None
        twa_newLevel = None
        capecs = capecs.split(",")
        for capec in capecs:
            twa_tmp = None
            twa_newLevel_tmp = None
            if capec != "??":
                logger.info(f"[alert {alertid}] Found CAPEC {capec} for mapped WASC {wascid}")
                twa_tmp, twa_newLevel_tmp = self._twaMappingSearch(capec, self._capecMappings)
                if twa_tmp == None:
                    logger.info(f"[alert {alertid}] Unsupported CAPEC {capec} missing TWA in mapping")
                    self._skippedAlerts['capecUnsupported'][alertid] = {"alertid":alertid, "capecid":capec, "reason":f"Unsupported CAPEC {capec} missing TWA in CAPEC"}
                else:
                    logger.info(f"[alert {alertid}] Found {twa_tmp} with level {twa_newLevel_tmp}")
            else:
                logger.info(f"[alert {alertid}] CAPEC not in WASC {wascid} of ZAP alert")
                self._skippedAlerts['capecUnsupported'][alertid] = {"alertid":alertid, "capecid":capec, "reason":f"CAPEC not in WASC {wascid} of ZAP alert"}

            twa, twa_newLevel = self._returnWorstTWAAndLevel(twa, twa_newLevel, twa_tmp, twa_newLevel_tmp)

        return twa, twa_newLevel
    
    def _findOwasp2010TWAsAndLevel(self, owasp2010s:str, wascid, alertid):
        # Add in a check here to see if there's a OWASP Top Ten info can be mapped in
        twa = None
        twa_newLevel = None
        owasp2010s = owasp2010s.split(",")
        for owasp2010 in owasp2010s:
            twa_tmp = None
            twa_newLevel_tmp = None
            if owasp2010 != "??":
                logger.info("[alert {}] Found OWASP 2010 {} for mapped WASC {}".format(alertid, owasp2010, wascid))

                twa_tmp, twa_newLevel_tmp = self._twaMappingSearch(owasp2010, self._owasp2010Mappings)
                if twa_tmp == None:
                    logger.info("[alert {}] Unsupported OWASP 2010 {} missing TWA in mapping".format(alertid, owasp2010))
                    self._skippedAlerts['owasp2010Unsupported'][alertid] = {"alertid":alertid, "owasp2010id":owasp2010, "reason":"Unsupported OWASP 2010 {} missing TWA in mapping".format(owasp2010)}
                else:
                    logger.info(f"[alert {alertid}] Found {twa_tmp} with level {twa_newLevel_tmp}")
            else:
                logger.info(f"[alert {alertid}] OWASP 2010 not in WASC {wascid} of ZAP alert")
                self._skippedAlerts['owasp2010Unsupported'][alertid] = {"alertid":alertid, "owasp2010id":owasp2010, "reason":f"OWASP 2010 not in WASC {wascid} of ZAP alert"}

            twa, twa_newLevel = self._returnWorstTWAAndLevel(twa, twa_newLevel, twa_tmp, twa_newLevel_tmp)

        return twa, twa_newLevel

    def _findSansTWAsAndLevel(self, sans:str, wascid, alertid):
        # Look to see if there's a SANS/CWE Top 25 2009 info that's mapped to the WASC
        twa = None
        twa_newLevel = None
        sans = sans.split(",")
        for san in sans:
            twa_tmp = None
            twa_newLevel_tmp = None
            if san != "??":
                logger.info(f"[alert {alertid}] Found SANS/CWE 2009 {san} for mapped WASC {wascid}")
                twa_tmp, twa_newLevel_tmp = self._twaMappingSearch(san, self._cweMappings)
                if twa_tmp == None:
                    logger.info(f"[alert {alertid}] Unsupported SANS/CWE 2009 {san} missing TWA in mapping")
                    self._skippedAlerts['sans2009Unsupported'][alertid] = {"alertid":alertid, "san2009id":san, "reason":f"Unsupported SANS/CWE 2009 {san} missing TWA in mapping"}
                else:
                    logger.info(f"[alert {alertid}] Found {twa_tmp} with level {twa_newLevel_tmp}")
            else:
                logger.info(f"[alert {alertid}] SANS/CWE 2009 not in WASC {wascid} of ZAP alert")
                self._skippedAlerts['sans2009Unsupported'][alertid] = {"alertid":alertid, "san2009id":san, "reason":f"SANS/CWE 2009 not in WASC {wascid} of ZAP alert"}

            twa, twa_newLevel = self._returnWorstTWAAndLevel(twa, twa_newLevel, twa_tmp, twa_newLevel_tmp)

        return twa, twa_newLevel

    def _findWascCweTWAsAndLevel(self, cwe, wascid, alertid):
        # Look to see if there's a CWE that's mapped from the WASC
        logger.info(f"[alert {alertid}] Searching for CWE {cwe} for mapped WASC {wascid}")
        return self._findCweTWAsAndLevel(cwe, alertid)


class ZapMappings(AlertMappings):
    def __init__(self, cweMappingFile, wascMappingFile, capecMappingFile, owasp2010MappingFile):

        self._cweMappingFile = cweMappingFile
        self._wascMappingFile = wascMappingFile
        self._capecMappingFile = capecMappingFile
        self._owasp2010MappingFile = owasp2010MappingFile

        self._skippedAlerts = {"zapUnsupported":{},
                               "zapFalsePositive":{},
                               "zapInformationalRiskcode":{},
                               "zapNotWorse":{},
                               "cweUnsupported":{},
                               "wascUnsupported":{},
                               "capecUnsupported":{},
                               "owasp2010Unsupported":{},
                               "sans2009Unsupported":{}}
        
        logger.info("Reading in CWE mappings")
        self._cweMappings = self.readInCWEs()
        logger.info("Reading in WASC mappings")
        self._wascMappings = self.readInWASCs()
        logger.info("Reading in CAPEC mappings")
        self._capecMappings = self.readInCAPECs()
        logger.info("Reading in OWASP Top 10 2010 mappings")
        self._owasp2010Mappings = self.readInOWASPTop102010()
        
        self._zapReport = None

    def _riskcodeToRiskLevel(self, riskcode):
        if riskcode == 4:
            return "VeryHigh"
        elif riskcode == 3:
            return "High"
        elif riskcode == 2:
            return "Medium"
        elif riskcode == 1:
            return "Low"
        elif riskcode == 0:
            return "VeryLow"
        
    def _riskcodeToTWALevel(self, riskcode):
        if riskcode == 4:
            return "VeryLow"
        elif riskcode == 3:
            return "Low"
        elif riskcode == 2:
            return "Medium"
        elif riskcode == 1:
            return "High"
        elif riskcode == 0:
            return "VeryHigh"

    def getBaseTWAs(self):

        if DOMAIN_MODEL_VERSION == 5:
            extrinsic_xs = "Extrinsic-XS"
        elif DOMAIN_MODEL_VERSION == 4:
            extrinsic_xs = "Extrinsic-SX"
        else:
            logger.debug(f"Matching domain model version number not found, DOMAIN_MODEL_VERSION {DOMAIN_MODEL_VERSION}")
            extrinsic_xs = "Extrinsic-XS"

        return {extrinsic_xs:None,
                "Extrinsic-QI":None,
                "Extrinsic-M":None,
                "Extrinsic-U":None,
                "Extrinsic-C":None,
                "Extrinsic-I":None,
                "Extrinsic-A":None,
                "Extrinsic-O":None,
                "Extrinsic-VN":None,
                "Extrinsic-AU":None}

    def processZapAlerts(self, alert, authenticated_scan: bool):
        logger.info(f"[alert {alert.pluginid}] Begining ZAP mapping process")

        self._newTWAs = self.getBaseTWAs()

        # If the confidence of the ZAP alert corresponds to a false positive
        # then skip it, else consider the detected vuln to be genuine.
        if alert.confidence == 0:
            logger.info(f"[alert {alert.pluginid}] False positive confidence level, skipping ZAP alert...")
            self._skippedAlerts['zapFalsePositive'][alert.pluginid] = {"alertid":alert.pluginid, "reason":"False positive"}
        elif alert.riskcode == 0:
            logger.info(f"[alert {alert.pluginid}] Informational riscode level, skipping ZAP alert...")
            self._skippedAlerts['zapInformationalRiskcode'][alert.pluginid] = {"alertid":alert.pluginid, "reason":"Informational riskcode level"}
        else:

            twa = None
            twa_newLevel = None

            # Check to see if ZAP alert has CWE info, and if so if that CWE is in
            # the CWE mappings and has TWA scope info present.
            if alert.cweid != None:
                if alert.cweid in self._cweMappings.keys():
                    logger.info(f"[alert {alert.pluginid}] Found CWE {alert.cweid} in ZAP alert")

                    # Search the CWE mappings to try and find a TWA that corresponds to the ZAP alert
                    if twa == None:
                        twa, twa_newLevel = self._findCweTWAsAndLevel(alert.cweid, alert.pluginid)

                else:
                    logger.info(f"[alert {alert.pluginid}] Unsupported CWE {alert.cweid} not in CWE mapping")
                    self._skippedAlerts['cweUnsupported'][alert.pluginid] = {"alertid":alert.pluginid, "cweid":alert.cweid, "reason":f"Unsupported CWE {alert.cweid} not in CWE mapping"}
            elif twa == None:
                logger.info(f"[alert {alert.pluginid}] CWE not in ZAP alert")
                self._skippedAlerts['cweUnsupported'][alert.pluginid] = {"alertid":alert.pluginid, "cweid":None, "reason":f"CWE not in ZAP alert"}

            # Check if ZAP alert has a WASC, if so then check the WASC mapping to see if
            # suitable CAPECs, OWASPs, or SANS are present and have the required info.
            if alert.wascid != None and twa == None:
                if alert.wascid in self._wascMappings.keys() and twa == None:
                    logger.info(f"[alert {alert.pluginid}] Found WASC {alert.wascid} in ZAP alert")
                
                    # If there was no TWA found in the CWE mappings then search the CAPEC mappings
                    if twa == None:
                        twa, twa_newLevel = self._findCapecTWAsAndLevel(self._wascMappings[alert.wascid]['CAPEC ID'], alert.wascid, alert.pluginid)
                        
                    # If there was no TWA found in the CWE and CAPEC mappings then search the OWASP Top 10 2010 mappings
                    if twa == None:
                        twa, twa_newLevel = self._findOwasp2010TWAsAndLevel(self._wascMappings[alert.wascid]['OWASP Top Ten 2010'], alert.wascid, alert.pluginid)
                    
                    # If there was no TWA found in the CWE, CAPEC, and OWASP Top 10 2010 mappings then search the SANS/CWE Top 25 2009 mappings
                    if twa == None:
                        twa, twa_newLevel = self._findSansTWAsAndLevel(self._wascMappings[alert.wascid]['SANS/CWE Top 25 2009'], alert.wascid, alert.pluginid)

                    # If there was no TWA found in the CWE, CAPEC, OWASP Top 10 2010 mappings, and SANS/CWE Top 25 2009 mappings then search the WASC-CWE mappings
                    if twa == None:
                        twa, twa_newLevel = self._findWascCweTWAsAndLevel(self._wascMappings[alert.wascid]['CWE ID'], alert.wascid, alert.pluginid)

                else:
                    logger.info(f"[alert {alert.pluginid}] Unsupported WASC {alert.wascid} not in WASC mapping")
                    self._skippedAlerts['wascUnsupported'][alert.pluginid] = {"alertif":alert.pluginid, "wascid":alert.wascid, "reason":f"Unsupported WASC {alert.wascid} not in WASC mapping"}
                    
            elif twa == None:
                logger.info(f"[alert {alert.pluginid}] WASC not in ZAP alert")
                self._skippedAlerts['wascUnsupported'][alert.pluginid] = {"alertif":alert.pluginid, "wascid":None, "reason":f"WASC not in ZAP alert"}

            if twa == None:
                    logger.info(f"[alert {alert.pluginid}] Unsupported ZAP alert")
                    self._skippedAlerts['zapUnsupported'][alert.pluginid] = {"alertid":alert.pluginid, "reason":f"Unsupported ZAP alert"}
            else:

                # Each TWA can be a list of a couple of TWAs so we need to cycle through them all
                logger.info(f"[alert {alert.pluginid}] {len(twa)} TWA(s) to check for within alert")
                for twa_sub in twa:

                    # If we're using v4 of the domain model then the XSS TWA is called "Extrinsic-SX" rather than "Extrinsic-XS"
                    # so update it's name to reflect that as it's called "Extrinsic-XS" in the various mapping files.
                    if DOMAIN_MODEL_VERSION == 4 and twa_sub == "Extrinsic-XS":
                        twa_sub = "Extrinsic-SX"

                    # Approximate TWA level to "inverse" of risk level if TWA level missing
                    if twa_newLevel == None or twa_newLevel == "??":
                        logger.info(f'[alert {alert.pluginid}] TWA level missing, approximating to "inverse" of ZAP risk level "{self._riskcodeToRiskLevel(alert.riskcode)}" to give "{self._riskcodeToTWALevel(alert.riskcode)}"')
                        twa_newLevel = self._riskcodeToTWALevel(alert.riskcode)

                    # If ZAP riskcode is low then we want to include the effects of the detected vulnerability but only to a
                    # limited extent so that the low ZAP risks do not swamp the more important medium and high risks.
                    if alert.riskcode == 1:
                        logger.info(f'[alert {alert.pluginid}] Limiting TWA level reduction to High due to Low ZAP risk level')
                        twa_newLevel = "High"

                    # If the twa value is "Extrinsic-M or Extrinsic-U" we need to decide which one of the two it is. We can do
                    # this by assuming that a ZAP risk of High corresponds to Extrinsic-M and Low or Medium to Extrinsic-U.
                    if twa_sub == "Extrinsic-M or Extrinsic-U":
                        if alert.riskcode > 2:
                            twa_sub = "Extrinsic-M"
                        else:
                            twa_sub = "Extrinsic-U"

                    # If the twa value is "Extrinsic-A or Extrinsic-O" we need to decide which one of the two it is. We can do
                    # this by assuming that a ZAP risk of medium or higher corresponds to Extrinsic-A and lower to Extrinsic-O.
                    if twa_sub == "Extrinsic-A or Extrinsic-O":
                        if alert.riskcode > 2:
                            twa_sub = "Extrinsic-A"
                        else:
                            twa_sub = "Extrinsic-A"

                    # Assume all vulns. from ZAP reports can be exploited from a remote network connect and set Extrinsic-VN to
                    # the new TWA level
                    self._newTWAs['Extrinsic-VN'] = twa_newLevel

                    # If the attacker does not need to be authenticated to exploit the found weakness/vulnerability then we
                    # reduce the TWA Extrinsic-AU, and if they do need to authenticate then we leave that TWA alone. We
                    # deduce whether they are or not based on whether the ZAP report comes from an authenticated or
                    # unauthenticated ZAP scan.
                    if authenticated_scan == False:
                        self._newTWAs['Extrinsic-AU'] = twa_newLevel

                    if self._newTWAs[twa_sub] == None:
                        logger.info(f"[alert {alert.pluginid}] Setting tmp TWA {twa_sub} to {twa_newLevel}")
                        self._newTWAs[twa_sub] = twa_newLevel
                    elif TWALevel[twa_newLevel.upper()] < TWALevel[self._newTWAs[twa_sub].upper()]:
                        logger.info(f"[alert {alert.pluginid}] Changing tmp TWA {twa_sub}: {self._newTWAs[twa_sub]} -> {twa_newLevel}")
                        self._newTWAs[twa_sub] = twa_newLevel
                    else:
                        logger.info(f"[alert {alert.pluginid}] Change to tmp TWA {twa_sub} does not make tmp TWA worse, keeping previous value")
                        self._skippedAlerts['zapNotWorse'][alert.pluginid] = {"alertid":alert.pluginid, "reason":f"Change to tmp TWA {twa_sub} does not make tmp TWA worse, keeping previous value"}
                        
        logger.info(f"[alert {alert.pluginid}] Returning found TWA value(s) from ZAP alert")
        return self._newTWAs
