import os

from dotenv import load_dotenv

from json import JSONDecodeError

from app.ssm.ssm_client import TWALevel
from app.clients.tai_la_client import login, result

from app.core.config import TAI_LA_USER, TAI_LA_PASS

from fastapi.logger import logger


def get_tai_la_results(user_id):
    
    # Placeholders for now, case_id and asset_ids will be determined from the user_id in the future
    case_id = "Port"
    asset_ids = ["0"]#, "1", "2", "3", "4"]
        
    # Loop over and retrive fairness, accuracy, and robustness TAI LA results
    characteristics = ["fairness", "accuracy", "robustness"]
    characteristics_results = {}
    
    # Auth first
    access_token, _ = login(TAI_LA_USER, TAI_LA_PASS)
    
    characteristics_results = {}
    for asset_id in asset_ids:
        characteristics_results[asset_id] = {}
        for characteristic in characteristics:
            try:
                tmp = result(access_token, asset_id, case_id, characteristic)
                logger.info(f"Retrieved characteristic results for {characteristic}")
                characteristics_results[asset_id][characteristic] = {}
                for key, assessment_result in tmp['assessment_results'].items():
                    for assessment_item in assessment_result:
                        characteristics_results[asset_id][characteristic][assessment_item['name']] = assessment_item
                        logger.info(f"    Retrieved metric {assessment_item['name']}")
                
            except JSONDecodeError as err:
                logger.error("Could not retrieve characteristic result due to JSONDecodeError error")
                raise Exception(f"Get TAI LA result failed with error: {err}")
                
            except:
                logger.error("Could not retrieve characteristic result")
                raise Exception("Get TAI LA result failed")
            
    return characteristics_results

def bin_tw(value):
    if value == 1.0:
        return "Safe"
    elif value > 0.9:
        return "VeryHigh"
    elif value > 0.8:
        return "High"
    elif value > 0.7:
        return "Medium"
    elif value > 0.5:
        return "Low"
    else:
        return "VeryLow"

def process_characteristics_results(characteristics_results):
    # Just a first pass approximation  to later be improved upon
    logger.info("Processing characteristics results...")
    for asset_id, characteristics_r in characteristics_results.items():
        logger.info(f"Processing for asset ID '{asset_id}'")
        for characteristic_name, characteristic in characteristics_r.items():
            logger.info(f"  Processing {characteristic_name}")
            worst_tw_level = "VeryHigh"
            for result_name, result in characteristic.items():

                if not type(result['value']) is list:
                    value = [result['value']]
                else:
                    value = result['value']
                    
                if result['value_range'] == "-":
                    value_range = "0 to 1"
                    target_value = 1.0
                else:
                    value_range = result['value_range']
                    target_value = result['target_value']
                    
                for val in value:
                    tw_level = "VeryHigh"
                    
                    if value_range == "0 to 1":
                        if float(target_value) == 0.0:
                            tw_level = bin_tw(1 - val)
                        elif float(target_value) == 1.0:
                            tw_level = bin_tw(val)
                        else:
                            logger.info(f"    Unsupported target value found of {result['target_value']}")
                            tw_level = bin_tw(val)
                    
                    elif value_range == "-1 to 1":
                        if float(target_value) == 0.0:
                            tw_level = bin_tw(1 - abs(val))
                        else:
                            tw_level = bin_tw(1 - abs(val))
                    
                    elif value_range == "0 to infinity":
                        threshold = 1.0
                        if val > threshold:
                            tw_level = tw_level = "VeryLow"
                        else:
                            if float(target_value) == 0.0:
                                tw_level = bin_tw(1 - val / threshold)
                            elif float(target_value) == 1.0:
                                if val <= 1:
                                    tw_level = bin_tw(val)
                                else:
                                    norm = 1 - ((val - 1) / val)
                                    if norm < 0:
                                        norm = 0
                            else:
                                logger.info(f"    Unsupported target value found of {result['target_value']}")
                                tw_level = bin_tw(val)
                                
                    else:
                        logger.info("    Unsupported value range")
                
                logger.info(f"    {result_name}: value {val}, range {result['value_range']}, target {result['target_value']} to {tw_level}")
            
                if TWALevel[tw_level.upper()].value < TWALevel[worst_tw_level.upper()].value:
                    worst_tw_level = tw_level
                    
                characteristics_results[asset_id][characteristic_name][result_name]['tw_level'] = worst_tw_level
        
    return characteristics_results

def apply_characteristics_results(characteristics_results):
    
    logger.info("Applying characteristics results to Spyderisk system model...")
    
    # Find model key from user ID
    model_key = "23rdf_placebolder"
    logger.info("  Finding corresponding Spyderisk system model based on the user ID")
    
    changes = {}
    for asset_id, characteristics_r in characteristics_results.items():
        
        # Find asset in Spyderisk based on the meta data
        logger.info(f"  Finding system asset for TAI LA asset '{asset_id}'")
        
        for characteristic_name, characteristic in characteristics_r.items():
    
            # Map the characteristic to the TWA
            logger.info(f"  Mapping characteristic '{characteristic_name}' to {characteristic_name} TWA")
            
            # Collate results, take the worst
            worst_result_level = "VeryHigh"
            for result_name, result in characteristic.items():
                if TWALevel[result['tw_level'].upper()].value < TWALevel[worst_result_level.upper()].value:
                    worst_result_level = result['tw_level']
                    
            logger.info(f"    Worst TWA level found: {worst_result_level}")

            # Update TWA to this new level, if this level is worse than the current TWA level
            logger.info(f"    Updating TWA corresponding to characteristic '{characteristic_name}' to level '{worst_result_level}'")
            changes[characteristic_name] = worst_result_level
            
            # Should also store the changes so they can be reverted...
            logger.info("    Storing TWA change so it can be reverted...")

    return changes
            
def run_risk_calc():
    # Placeholder function to call the risk calculation
    logger.info("Running risk calculation based on these new values...")
    
def revert_TWA_level():
    # Placeholder function to revert the TWA levels
    logger.info("Reverting TWA levels back to prior default+user-set levels...")
