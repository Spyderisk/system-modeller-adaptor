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
##      Created Date :          2022-06-15
##      Created for Project :   Cyberkit4SME
##
##///////////////////////////////////////////////////////////////////////


import subprocess
import platform
import os
import datetime as dt


def findFilesNewerThanFile(files_location, timestamp_file):
    if files_location[-1] != "/":
        files_location = files_location + "/"
    files = []
    if platform.system() == "Linux" or platform.system() == "Darwin":
        find = subprocess.Popen('find ' + files_location + ' -type f -newer ' + timestamp_file, shell=True, 
                                stdout=subprocess.PIPE)
        for line in find.stdout:
            files.append(line.decode('UTF-8').strip())
    else:
        timestamp = dt.datetime.fromtimestamp(os.stat(".timestamp").st_mtime)
        for file in os.listdir(files_location):
            if dt.datetime.fromtimestamp(os.stat(file).st_mtime) > timestamp:
                files.append(files_location + file)

    return files

def findFilesInLocation(files_location):
    files = []
    for file in os.listdir(files_location):
        files.append(files_location + file)

    return files