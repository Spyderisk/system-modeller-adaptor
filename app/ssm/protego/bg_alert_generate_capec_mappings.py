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

class CAPEC_GenerateMappings:
    def __init__(self):
        self._extrinsic_MorU = "Extrinsic-M or Extrinsic-U"
        self._extrinsic_C =    "Extrinsic-C"
        self._extrinsic_I =    "Extrinsic-I"
        self._extrinsic_AorO = "Extrinsic-A or Extrinsic-O"
        self._extrinsic_XS =   "Extrinsic-XS"
        self._extrinsic_QI =   "Extrinsic-QI"
    
    def readin(self, file):
        '''
        Reads in the CAPEC XML file.

        Uses xmldict to read the XML file in to an ordered dictionary.
        Structure of the ordered dict is:
            - Attack_Pattern_Catalog [ordered dict]
                - Attack_Patterns    [ordered dict]
                    - Attack Pattern [ordered dict]
                        - @ID                    [str]
                        - @Name                  [str]
                        - @Status                [str]
                        - Description            [str or list in ordered dict]
                        - Likelihood_Of_Attack   [str]
                        - Typical_Severity       [str]
                        - Skills_Required        [ordered dict]
                            - Skill              [list or ordered dict]
                                - @Level         [str]
                        - Consequences           [list or ordered dict]
                            - Consequence        [list or ordered dict]
                                - Scope          [list or str]
        
                - Categories   [ordered dict]
                    - Category [ordered dict]
                        - @ID           [str]
                        - @Name         [str]
                        - @Status       [str]
                        - Summary       [str]
                        - Relationships [ordered dict]
                            - Has_Member    [ordered dict]
                                - @CAPEC_ID [str]

        Parameters
        ----------
        file : str
               The CAPEC XML file to read in.

        Returns
        -------
        (None)
        '''
        self._fieldNames = ["ID", "Name", "Description", "Type", "Likelihood of Attack", "Typical Severity", "Skill Level Required", "Scope"]
        
        with open(file, encoding='utf-8') as fd:
            CAPEC_dict = xmltodict.parse(fd.read())
    
        capec_attackPatterns = {item["@ID"]:item for item in CAPEC_dict['Attack_Pattern_Catalog']['Attack_Patterns']['Attack_Pattern']}
        self._capec_attackPatterns = {key:{} for key in capec_attackPatterns.keys()}
        
        capec_categories = {item["@ID"]:item for item in CAPEC_dict['Attack_Pattern_Catalog']['Categories']['Category']}
        self._capec_categories = {key:{} for key in capec_categories.keys()}
        
        for key in capec_attackPatterns.keys():
            self._capec_attackPatterns[key]["ID"] = capec_attackPatterns[key]["@ID"]
            self._capec_attackPatterns[key]["Name"] = capec_attackPatterns[key]["@Name"]
            self._capec_attackPatterns[key]["Status"] = capec_attackPatterns[key]["@Status"]
            # If we want to include Description then it needs a bit more thought as Description
            # can also be a list within an ordered dict
            if isinstance(capec_attackPatterns[key]["Description"], str):
                self._capec_attackPatterns[key]["Description"] = capec_attackPatterns[key]["Description"]
            else:
                self._capec_attackPatterns[key]["Description"] = "??"
            self._capec_attackPatterns[key]["Type"] = "AttackPattern"
            if "Likelihood_Of_Attack" in capec_attackPatterns[key].keys():
                self._capec_attackPatterns[key]["Likelihood of Attack"] = capec_attackPatterns[key]["Likelihood_Of_Attack"].replace(" ", "")
            else:
                self._capec_attackPatterns[key]["Likelihood of Attack"] = "??"
            if "Typical_Severity" in capec_attackPatterns[key].keys():
                self._capec_attackPatterns[key]["Typical Severity"] = capec_attackPatterns[key]["Typical_Severity"]
            else:
                self._capec_attackPatterns[key]["Typical Severity"] = "??"
            # Needs a bit more thought as Skill can be list of ordered dicts
            #if "Skills_Required" in capec_attackPatterns[key].keys() and "Skill" in capec_attackPatterns[key]["Skills_Required"].keys():
            #    self._capec_attackPatterns[key]["Skill Level Required"] = capec_attackPatterns[key]["Skills_Required"]["Skill"]["@Level"]
            #else:
            #    self._capec_attackPatterns[key]["Skill Level Required"] = "??"
            self._capec_attackPatterns[key]["Skill Level Required"] = "??"
            if "Consequences" in capec_attackPatterns[key].keys():
                self._capec_attackPatterns[key]["Scope"] = ""
                if isinstance(capec_attackPatterns[key]["Consequences"]["Consequence"], list):
                    for item in capec_attackPatterns[key]["Consequences"]["Consequence"]:
                        if isinstance(item, list):
                            for it in item:
                                if it not in self._capec_attackPatterns[key]["Scope"]:
                                    self._capec_attackPatterns[key]["Scope"] += ", {}".format(it)
                        else:
                            item = item["Scope"]
                            if isinstance(item, list):
                                for it in item:
                                    if it not in self._capec_attackPatterns[key]["Scope"]:
                                        self._capec_attackPatterns[key]["Scope"] += ", {}".format(it)
                            else:
                                if item not in self._capec_attackPatterns[key]["Scope"]:
                                    self._capec_attackPatterns[key]["Scope"] += ", {}".format(item)
                else:
                    if isinstance(capec_attackPatterns[key]["Consequences"]["Consequence"]["Scope"], list):
                        for scope in capec_attackPatterns[key]["Consequences"]["Consequence"]["Scope"]:
                            if scope not in self._capec_attackPatterns[key]["Scope"]:
                                self._capec_attackPatterns[key]["Scope"] += ", {}".format(scope)
                    else:
                        if capec_attackPatterns[key]["Consequences"]["Consequence"]["Scope"] not in self._capec_attackPatterns[key]["Scope"]:
                            self._capec_attackPatterns[key]["Scope"] += ", {}".format(capec_attackPatterns[key]["Consequences"]["Consequence"]["Scope"])
            else:
                self._capec_attackPatterns[key]["Scope"] = "??"
                
            if self._capec_attackPatterns[key]["Scope"][0:2] == ", ":
                self._capec_attackPatterns[key]["Scope"] = self._capec_attackPatterns[key]["Scope"][2::]
                
        for key in capec_categories.keys():
            self._capec_categories[key]["ID"] = capec_categories[key]["@ID"]
            self._capec_categories[key]["Name"] = capec_categories[key]["@Name"]
            self._capec_categories[key]["Status"] = capec_categories[key]["@Status"]
            self._capec_categories[key]["Description"] = capec_categories[key]["Summary"]
            self._capec_categories[key]["Type"] = "Category"
            # CWE Categories don't have a likelihood of exploit, scope, skill level, or severity
            self._capec_categories[key]["Likelihood of Attack"] = "??"
            self._capec_categories[key]["Skill Level Required"] = "??"
            self._capec_categories[key]["Typical Severity"] = "??"
            self._capec_categories[key]["Scope"] = "??"
                
    def outputCSV(self, fileName, fileType="csv", what="Both"):
        '''
        Outputs the formatted CAPEC AttackPatterns to a CSV file.

        Parameters
        ----------
        fileName : str
                   File name of the output file.
        what : str
               What to output, CAPEC Attack Patterns, Categories, or both, using "AttackPatterns", "Categories", or "Both" to choose.

        Returns
        -------
        (None)
        '''
        if fileType == "csv":
            if len(fileName) >= 4 and fileName[-4:] != ".csv":
                fileName += ".csv"
            with open(fileName, mode="w", newline="") as csv_output:

                writer = csv.DictWriter(csv_output, fieldnames=self._fieldNames)
                writer.writeheader()
                
                if what == "AttackPatterns" or what == "Both":
                    capec_attackPatterns_output = collections.OrderedDict((key, {}) for key in [str(j) for j in sorted([int(i) for i in self._capec_attackPatterns.keys()])])
                    for key in self._capec_attackPatterns.keys():
                        capec_attackPatterns_output[key] = { alert_key: self._capec_attackPatterns[key][alert_key] for alert_key in self._fieldNames }
                        
                    for attack in capec_attackPatterns_output:
                        writer.writerow(capec_attackPatterns_output[attack])
                    
                if what == "Categories" or what == "Both":
                    capec_categories_output = collections.OrderedDict((key, {}) for key in [str(j) for j in sorted([int(i) for i in self._capec_categories.keys()])])
                    for key in self._capec_categories.keys():
                        capec_categories_output[key] = { alert_key: self._capec_categories[key][alert_key] for alert_key in self._fieldNames }
                        
                    for category in capec_categories_output:
                        writer.writerow(capec_categories_output[category])
        else:
            logger.error("Error, unsupported output file type.")
                    
    def find(self, what, where, AorC="AttackPatterns"):
        '''
        Searches the CAPEC Attack Patterns for key words/strings. Note, both
        the search string and the location to search are all reduced to all
        lower case letters during the search.

        Parameters
        ----------
        what : str
               The string to search for.
        where : str
                The locations to search in (e.g. "Name", "Description",
                "Scope", "Likelihood of Attack", etc.).
        AorC : str
               Specifies which CWE entry type to search ("AttackPatterns",
               "Categories, or "Both"). The default is "AttackPatterns"."

        Returns
        -------
        found : dict
                The CAPEC entries found from the search.
        '''
        found = {}
        
        if not isinstance(what, list):
            what = [what]
            
        if not isinstance(where, list):
            where = [where]

        if AorC == "AttackPatterns" or AorC == "Both":
            for item in what:
                for place in where:
                    for key in self._capec_attackPatterns.keys():
                        if item.lower() in self._capec_attackPatterns[key][place].lower() and key not in found.keys():
                            found[key] = self._capec_attackPatterns[key]
        if AorC == "Categories" or AorC == "Both":
            for item in what:
                for place in where:
                    for key in self._capec_categories.keys():
                        if item.lower() in self._capec_categories[key][place].lower() and key not in found.keys():
                            found[key] = self._capec_categories[key]
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
        TWAs to the CAPEC Attack Patterns. "Extrinsic-M or Extrinsic-U" if "Confidentiality", "Integrity",
        and "Availability" are all present in the Scope. Else, "Extrinsic-C" if "Confidentiality" in the
        Scope, "Extrinsic-I" if "Integrity" in the Scope, and "Extrinsic-A or Extrinsic-O" if "Availability"
        in the Scope.

        Parameters
        ----------
        (None)

        Returns
        -------
        (None)
        '''
        for key in self._capec_attackPatterns.keys():
            self._capec_attackPatterns[key]["TWA"] = "??"
            self._capec_attackPatterns[key]["TWA New Level"] = "??"
            if ("Confidentiality" in self._capec_attackPatterns[key]["Scope"] and \
               "Integrity" in self._capec_attackPatterns[key]["Scope"] and \
               "Availability" in self._capec_attackPatterns[key]["Scope"]) or ("Access Control" in self._capec_attackPatterns[key]["Scope"]):
                self._capec_attackPatterns[key]["TWA"] = "Extrinsic-M or Extrinsic-U"
                self._capec_attackPatterns[key]["TWA New Level"] = self._likelihoodToTW(self._capec_attackPatterns[key]["Likelihood of Attack"])
            else:
                if "Confidentiality" in self._capec_attackPatterns[key]["Scope"]:
                    self._capec_attackPatterns[key]["TWA"] += "Extrinsic-C,"
                    self._capec_attackPatterns[key]["TWA New Level"] = self._likelihoodToTW(self._capec_attackPatterns[key]["Likelihood of Attack"])
                if "Integrity" in self._capec_attackPatterns[key]["Scope"]:
                    self._capec_attackPatterns[key]["TWA"] += "Extrinsic-I,"
                    self._capec_attackPatterns[key]["TWA New Level"] = self._likelihoodToTW(self._capec_attackPatterns[key]["Likelihood of Attack"])
                if "Availability" in self._capec_attackPatterns[key]["Scope"]:
                    self._capec_attackPatterns[key]["TWA"] += "Extrinsic-A or Extrinsic-O,"
                    self._capec_attackPatterns[key]["TWA New Level"] = self._likelihoodToTW(self._capec_attackPatterns[key]["Likelihood of Attack"])
                    
                if len(self._capec_attackPatterns[key]["TWA"]) > 2 and self._capec_attackPatterns[key]["TWA"][0:2] == "??":
                    self._capec_attackPatterns[key]["TWA"] = self._capec_attackPatterns[key]["TWA"][2:]
                if len(self._capec_attackPatterns[key]["TWA"]) > 0 and self._capec_attackPatterns[key]["TWA"][-1] == ",":
                    self._capec_attackPatterns[key]["TWA"] = self._capec_attackPatterns[key]["TWA"][0:-1]
        
    def _addXSSAndQITWAs(self):
        '''
        Search CAPEC names and desfriptions to find CAPECs related to cross-site and query-injection
        vulnerabilities, then set their corresponding TWAs to Extrinsic-XS and Extrinsic-QI respectively,
        as well  as their TWA New Levels to the "inverse" of their Likelihood of Attack levels

        Parameters
        ----------
        (None)

        Returns
        -------
        (None)
        '''
        xss_list = self.find(what=["cross site", "cross-site", "XSS"], where=["Name", "Description"], AorC="AttackPatterns")
        qi_list = self.find(what=["query injection", "query-injection", "qi",
                                  "sql injection", "improper neutralization of special"], where=["Name", "Description"], AorC="AttackPatterns")
        
        for key in xss_list.keys():
            self._capec_attackPatterns[key]["TWA"] = self._extrinsic_XS
            self._capec_attackPatterns[key]["TWA New Level"] = self._likelihoodToTW(self._capec_attackPatterns[key]["Likelihood of Attack"])
        for key in qi_list.keys():
            self._capec_attackPatterns[key]["TWA"] = self._extrinsic_QI
            self._capec_attackPatterns[key]["TWA New Level"] = self._likelihoodToTW(self._capec_attackPatterns[key]["Likelihood of Attack"])

    def createCSVMappingFile(self, inputfile, outputfile="app/static/mappings/capec"):
        '''
        Create CAPEC CSV mapping file from CAPEC XML input file. CAPEC XML input file can be downloaded from, for
        example, https://capec.mitre.org/data/xml/capec_latest.xml

        Parameters
        ----------
        inputfile : str
                    The CAPEC XML input file.
        outputfile : str
                     The CAPEC CSV output file to output to.

        Returns
        -------
        (None)
        '''
        logger.info(f"Creating CAPEC CSV mapping file")
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
        logger.info(f"Outputting CAPEC CSV file to {outputfile}")
        self.outputCSV(fileName=outputfile, what="AttackPatterns")
        logger.info(f"Created CAPEC CSV mapping file")
