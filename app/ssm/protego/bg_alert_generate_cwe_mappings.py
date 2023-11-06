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
##      Created Date :          2021-05-04
##      Created for Project :   ProTego
##
##///////////////////////////////////////////////////////////////////////

import csv
import collections
import xmltodict

from fastapi.logger import logger

class CWE_GenerateMappings:
    def __init__(self):
        self._extrinsic_MorU = "Extrinsic-M or Extrinsic-U"
        self._extrinsic_C =    "Extrinsic-C"
        self._extrinsic_I =    "Extrinsic-I"
        self._extrinsic_AorO = "Extrinsic-A or Extrinsic-O"
        self._extrinsic_XS =   "Extrinsic-XS"
        self._extrinsic_QI =   "Extrinsic-QI"
    
    def readin(self, file):
        '''
        Reads in the CWE XML file.

        Uses xmldict to read the XML file in to an ordered dictionary.
        Structure of the ordered dict is:
            - Weakness_Catalog [ordered dict]
                - Weaknesses   [ordered dict]
                    - Weakness [ordered dict]
                        - ID                    [str]
                        - Name                  [str]
                        - Status                [str]
                        - Description           [str]
                        - Likelihood of exploit [str]
                        - Common_Consequences   [list or ordered dict]
                            - Consequence       [list or ordered dict]
                                - Scope         [list or str]
        
                - Categories   [ordered dict]
                    - Category [ordered dict]
                        - ID      [str]
                        - Name    [str]
                        - Status  [str]
                        - Summary [str]

        Parameters
        ----------
        file : str
               The CWE XML file to read in.

        Returns
        -------
        (None)
        '''
        self._fieldNames = ["ID", "Name", "Description", "Type", "Likelihood of Exploit", "Scope"]
        
        with open(file, encoding='utf-8') as fd:
            CWE_dict = xmltodict.parse(fd.read())
    
        cwe_weaknesses = {item["@ID"]:item for item in CWE_dict['Weakness_Catalog']['Weaknesses']['Weakness']}
        self._cwe_weaknesses = {key:{} for key in cwe_weaknesses.keys()}
        
        cwe_categories = {item["@ID"]:item for item in CWE_dict['Weakness_Catalog']['Categories']['Category']}
        self._cwe_categories = {key:{} for key in cwe_categories.keys()}
        
        for key in cwe_weaknesses.keys():
            self._cwe_weaknesses[key]["ID"] = cwe_weaknesses[key]["@ID"]
            self._cwe_weaknesses[key]["Name"] = cwe_weaknesses[key]["@Name"]
            self._cwe_weaknesses[key]["Status"] = cwe_weaknesses[key]["@Status"]
            self._cwe_weaknesses[key]["Description"] = cwe_weaknesses[key]["Description"]
            self._cwe_weaknesses[key]["Type"] = "Weakness"
            if "Likelihood_Of_Exploit" in cwe_weaknesses[key].keys():
                self._cwe_weaknesses[key]["Likelihood of Exploit"] = cwe_weaknesses[key]["Likelihood_Of_Exploit"].replace(" ", "")
            else:
                self._cwe_weaknesses[key]["Likelihood of Exploit"] = "??"
            if "Common_Consequences" in cwe_weaknesses[key].keys():
                self._cwe_weaknesses[key]["Scope"] = ""
                if isinstance(cwe_weaknesses[key]["Common_Consequences"]["Consequence"], list):
                    for item in cwe_weaknesses[key]["Common_Consequences"]["Consequence"]:
                        if isinstance(item, list):
                            for it in item:
                                if it not in self._cwe_weaknesses[key]["Scope"]:
                                    self._cwe_weaknesses[key]["Scope"] += ", {}".format(it)
                        else:
                            item = item["Scope"]
                            if isinstance(item, list):
                                for it in item:
                                    if it not in self._cwe_weaknesses[key]["Scope"]:
                                        self._cwe_weaknesses[key]["Scope"] += ", {}".format(it)
                            else:
                                if item not in self._cwe_weaknesses[key]["Scope"]:
                                    self._cwe_weaknesses[key]["Scope"] += ", {}".format(item)
                else:
                    if isinstance(cwe_weaknesses[key]["Common_Consequences"]["Consequence"]["Scope"], list):
                        for scope in cwe_weaknesses[key]["Common_Consequences"]["Consequence"]["Scope"]:
                            if scope not in self._cwe_weaknesses[key]["Scope"]:
                                self._cwe_weaknesses[key]["Scope"] += ", {}".format(scope)
                    else:
                        if cwe_weaknesses[key]["Common_Consequences"]["Consequence"]["Scope"] not in self._cwe_weaknesses[key]["Scope"]:
                            self._cwe_weaknesses[key]["Scope"] += ", {}".format(cwe_weaknesses[key]["Common_Consequences"]["Consequence"]["Scope"])
            else:
                self._cwe_weaknesses[key]["Scope"] = "??"
                
            if self._cwe_weaknesses[key]["Scope"][0:2] == ", ":
                self._cwe_weaknesses[key]["Scope"] = self._cwe_weaknesses[key]["Scope"][2::]
                
        for key in cwe_categories.keys():
            self._cwe_categories[key]["ID"] = cwe_categories[key]["@ID"]
            self._cwe_categories[key]["Name"] = cwe_categories[key]["@Name"]
            self._cwe_categories[key]["Status"] = cwe_categories[key]["@Status"]
            self._cwe_categories[key]["Description"] = cwe_categories[key]["Summary"]
            self._cwe_categories[key]["Type"] = "Category"
            # CWE Categories don't have a likelihood of exploit or scope
            self._cwe_categories[key]["Likelihood of Exploit"] = "??"
            self._cwe_categories[key]["Scope"] = "??"
                
    def outputCSV(self, fileName, what="Both"):
        '''
        Outputs the formatted CWE Weaknesses or Categories to a CSV file.

        Parameters
        ----------
        fileName : str
                   File name of the output file.
        what : str
               What to output, CWE Weaknesses, Categories, or both, using "Weaknesses", "Categories", or "Both" to choose.

        Returns
        -------
        (None)
        '''
        if len(fileName) >= 4 and fileName[-4:] != ".csv":
            fileName += ".csv"
        with open(fileName, mode="w", newline="") as csv_output:

            writer = csv.DictWriter(csv_output, fieldnames=self._fieldNames)
            writer.writeheader()
            
            if what == "Weaknesses" or what == "Both":
                cwe_weaknesses_output = collections.OrderedDict((key, {}) for key in [str(j) for j in sorted([int(i) for i in self._cwe_weaknesses.keys()])])
                for key in self._cwe_weaknesses.keys():
                    cwe_weaknesses_output[key] = { alert_key: self._cwe_weaknesses[key][alert_key] for alert_key in self._fieldNames }
                    
                for weakness in cwe_weaknesses_output:
                    writer.writerow(cwe_weaknesses_output[weakness])
                
            if what == "Categories" or what == "Both":
                cwe_categories_output = collections.OrderedDict((key, {}) for key in [str(j) for j in sorted([int(i) for i in self._cwe_categories.keys()])])
                for key in self._cwe_categories.keys():
                    cwe_categories_output[key] = { alert_key: self._cwe_categories[key][alert_key] for alert_key in self._fieldNames }
                    
                for category in cwe_categories_output:
                    writer.writerow(cwe_categories_output[category])
                    
    def find(self, what, where, WorC="Weaknesses"):
        '''
        Searches the CWE Weaknesses for key words/strings. Note, both the
        search string and the location to search are all reduced to all lower
        case letters during the search.

        Parameters
        ----------
        what : str
               The string to search for.
        where : str
                The locations to search in (e.g. "Name", "Description",
                "Scope", "Likelihood of Exploit", etc.).
        WorC : str
               Specifies which CWE entry type to search ("Weaknesses",
               "Categories, or "Both"). The default is "Weaknesses"."

        Returns
        -------
        found : dict
                The CWE entries found from the search.
        '''
        found = {}
        
        if not isinstance(what, list):
            what = [what]
            
        if not isinstance(where, list):
            where = [where]

        if WorC == "Weaknesses" or WorC == "Both":
            for item in what:
                for place in where:
                    for key in self._cwe_weaknesses.keys():
                        if item.lower() in self._cwe_weaknesses[key][place].lower() and key not in found.keys():
                            found[key] = self._cwe_weaknesses[key]
        if WorC == "Categories" or WorC == "Both":
            for item in what:
                for place in where:
                    for key in self._cwe_categories.keys():
                        if item.lower() in self._cwe_categories[key][place].lower() and key not in found.keys():
                            found[key] = self._cwe_categories[key]
        return found

    def _likelihoodToTW(self, likelihood):
        '''
        Returns the Trustworthiness value corresponding to a given Likelihood value.

        Parameters
        ----------
        likelihood : str
                     Input Likelihood value.

        Returns
        -------
        trustworthiness : str
                          Output corresponding Trustworthiness value.
        '''
        if likelihood == "VeryLow":
            return "VeryHigh"
        elif likelihood == "Low":
            return "High"
        elif likelihood == "Medium":
            return "Medium"
        elif likelihood == "High":
            return "Low"
        elif likelihood == "VeryHigh":
            return "VeryLow"
        elif likelihood == "??":
            return "??"
        else:
            logger.error(f"Unknown Likelihood of Exploit: {likelihood}")
            return "??"
        
    def _addBaseTWAs(self):
        '''
        Add the "Extrinsic-M or Extrinsic-U", "Extrinsic-C", "Extrinsic-I", and "Extrinsic-A or Extrinsic-O"
        TWAs to the CWE Attack Patterns. "Extrinsic-M or Extrinsic-U" if "Confidentiality", "Integrity", and
        "Availability" are all present in the Scope. Else, "Extrinsic-C" if "Confidentiality" in the Scope,
        "Extrinsic-I" if "Integrity" in the Scope, and "Extrinsic-A or Extrinsic-O" if "Availability" in the
        Scope.

        Parameters
        ----------
        (None)

        Returns
        -------
        (None)
        '''
        for key in self._cwe_weaknesses.keys():
            self._cwe_weaknesses[key]["TWA"] = "??"
            self._cwe_weaknesses[key]["TWA New Level"] = "??"
            if ("Confidentiality" in self._cwe_weaknesses[key]["Scope"] and \
                "Integrity" in self._cwe_weaknesses[key]["Scope"] and \
                "Availability" in self._cwe_weaknesses[key]["Scope"]) or ("Access Control" in self._cwe_weaknesses[key]["Scope"]):
                self._cwe_weaknesses[key]["TWA"] = self._extrinsic_MorU
                self._cwe_weaknesses[key]["TWA New Level"] = self._likelihoodToTW(self._cwe_weaknesses[key]["Likelihood of Exploit"])
            else:
                if "Confidentiality" in self._cwe_weaknesses[key]["Scope"]:
                    self._cwe_weaknesses[key]["TWA"] += self._extrinsic_C + ","
                    self._cwe_weaknesses[key]["TWA New Level"] = self._likelihoodToTW(self._cwe_weaknesses[key]["Likelihood of Exploit"])
                if "Integrity" in self._cwe_weaknesses[key]["Scope"]:
                    self._cwe_weaknesses[key]["TWA"] += self._extrinsic_I + ","
                    self._cwe_weaknesses[key]["TWA New Level"] = self._likelihoodToTW(self._cwe_weaknesses[key]["Likelihood of Exploit"])
                if "Availability" in self._cwe_weaknesses[key]["Scope"]:
                    self._cwe_weaknesses[key]["TWA"] += self._extrinsic_AorO + ","
                    self._cwe_weaknesses[key]["TWA New Level"] = self._likelihoodToTW(self._cwe_weaknesses[key]["Likelihood of Exploit"])
                    
                if len(self._cwe_weaknesses[key]["TWA"]) > 2 and self._cwe_weaknesses[key]["TWA"][0:2] == "??":
                    self._cwe_weaknesses[key]["TWA"] = self._cwe_weaknesses[key]["TWA"][2:]
                if len(self._cwe_weaknesses[key]["TWA"]) > 0 and self._cwe_weaknesses[key]["TWA"][-1] == ",":
                    self._cwe_weaknesses[key]["TWA"] = self._cwe_weaknesses[key]["TWA"][0:-1]
        
    def _addXSSAndQITWAs(self):
        '''
        Search CWE names and desfriptions to find CWEs related to cross-site and query-injection vulnerabilities,
        then set their corresponding TWAs to Extrinsic-XS and Extrinsic-QI respectively, as well  as their TWA
        New Levels to the "inverse" of their Likelihood of Attack levels.

        Parameters
        ----------
        (None)

        Returns
        -------
        (None)
        '''
        xss_list = self.find(what=["cross site", "cross-site", "XSS"], where=["Name", "Description"], WorC="Weaknesses")
        qi_list = self.find(what=["query injection", "query-injection", "qi",
                                  "sql injection", "improper neutralization of special"], where=["Name", "Description"], WorC="Weaknesses")
        
        for key in xss_list.keys():
            self._cwe_weaknesses[key]["TWA"] = self._extrinsic_XS
            self._cwe_weaknesses[key]["TWA New Level"] = self._likelihoodToTW(self._cwe_weaknesses[key]["Likelihood of Exploit"])
        for key in qi_list.keys():
            self._cwe_weaknesses[key]["TWA"] = self._extrinsic_QI
            self._cwe_weaknesses[key]["TWA New Level"] = self._likelihoodToTW(self._cwe_weaknesses[key]["Likelihood of Exploit"])

    def createCSVMappingFile(self, inputfile, outputfile="app/static/mappings/cwec"):
        '''
        Create CWE CSV mapping file from CWE XML input file. CWE XML input file can be downloaded from, for
        example, https://cwe.mitre.org/data/xml/cwec_latest.xml.zip

        Parameters
        ----------
        inputfile : str
                    The CWE XML input file.
        outputfile : str
                     The CWE CSV output file to output to.

        Returns
        -------
        (None)
        '''
        logger.info(f"Creating CWE CSV mapping file")
        logger.info(f"Reading in input XML file {inputfile}")
        self.readin(inputfile)
        logger.info(f"Setting output field names")
        self._fieldNames = ["ID", "Name", "TWA", "TWA New Level"]
        logger.info(f"Adding base TWAs")
        self._addBaseTWAs()
        logger.info(f"Adding XS and QI TWAs")
        self._addXSSAndQITWAs()
        if (not "/" in outputfile) and (not "\\" in outputfile):
            outputfile = "app/static/mappings/" + outputfile
        logger.info(f"Outputting CWE CSV file to {outputfile}")
        self.outputCSV(fileName=outputfile, what="Weaknesses")
        logger.info(f"Created CWE CSV mapping file")
