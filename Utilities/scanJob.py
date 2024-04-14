from pymongo import MongoClient
import clamd
import os
from dotenv import load_dotenv
import json

load_dotenv()

resultsPath = os.getenv("RESULTS_PATH")
cd = clamd.ClamdUnixSocket()

mongodbHost = os.getenv("MONGODB_HOST")
mongodbPort = int(os.getenv("MONGODB_PORT"))

client = MongoClient(mongodbHost, mongodbPort)
scan8 = client["scan8"]
queuedScans = scan8["queuedScans"]
runningScans = scan8["runningScans"]
completedScans = scan8["completedScans"]


# RQ job
def scan(filePath):
    id = filePath.split("/")[-2]
    name = filePath.split("/")[-1]
    queued = list(queuedScans.find({"_id": id}))
    if len(queued) != 0:
        runningScans.insert_one(queued[0])
        queuedScans.delete_one({"_id": id})
    # result = cd.scan(filePath)
    result = {
        "FileType": "Not supported Only c file",
        "Status": "Not Vulnerable",
        "VulnFunc": {},
    }
    vulfunc = {
        "strcpy": "strcpy_s",
        "strcat": "strcat_s",
        "gets": "fgets",
        "scanf": "scanf_s",
        "sprintf": "snprintf",
        "system": "execve",
        "memcpy": "memcpy_s",
        "memset": "memset_s",
        "rand": "rand_s",
        "fopen": "fopen_s",
        "fclose": "fclose",
        "fscanf": "fscanf_s",
        "fprintf": "fprintf_s",
        "sscanf": "sscanf_s",
        "gets_s": "fgets",
        "wcscpy": "wcscpy_s",
        "wcsncpy": "wcsncpy_s",
        "wcscat": "wcscat_s",
        "wcsncat": "wcsncat_s",
        "wcschr": "wcschr",
        "wcstok": "wcstok_s",
        "vfprintf": "vfprintf_s",
        "vprintf": "vprintf_s",
        "vsprintf": "vsprintf_s",
        "vsnprintf": "vsnprintf_s",
        "vscanf": "vscanf_s",
        "fwscanf": "fwscanf_s",
        "swscanf": "swscanf_s",
        "snwscanf": "snwscanf_s",
        "vfwprintf": "vfwprintf_s",
        "vswprintf": "vswprintf_s",
        "vsnwprintf": "vsnwprintf_s",
        "vfwscanf": "vfwscanf_s",
        "vswscanf": "vswscanf_s",
        "vsnwscanf": "vsnwscanf_s",
        "fread": "fread_s",
    }
    if filePath.endswith(".c"):
        result["FileType"] = "C file"
        for i in open(filePath, "r").readlines():
            for j in vulfunc:
                if j in i:
                    result["Status"] = "Vulnerable"
                    result["VulnFunc"][j] = vulfunc[j]
    else:
        result["FileType"] = "Not supported. Only C files are supported."

    filename = id + "_" + name + "_" + ".json"
    filename = resultsPath + "/" + filename
    with open(filename, "a+") as file:
        json.dump(result, file, indent=4)

    runningScans.update_one({"_id": id}, {"$inc": {"files.completed": 1}})

    running = list(runningScans.find({"_id": id}))
    if (
        len(running) != 0
        and running[0]["files"]["total"] == running[0]["files"]["completed"]
    ):
        completedScans.insert_one(running[0])
        runningScans.delete_one({"_id": id})
