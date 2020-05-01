import json
from botocore.exceptions import ClientError
import boto3
from datetime import datetime

timelog = []

def save_details(newEntry):
    global timelog
    ts0 = datetime.now().timestamp()
    s3 = initialize_s3()
    try:
        addrHistory = json.loads(load_file(s3, entries=True))
    except:
        addrHistory = {}
    entry = create_sign_entry(addrHistory, newEntry)
    upload_data(s3, entry)
    ts1 = datetime.now().timestamp()
    timelog.append(f" Upload Time: {str(ts1-ts0)}")
    return

def save_loglist(loglist):
    global timelog
    s3 = initialize_s3()
    try:
        logsOld = json.loads(load_file(s3, logs=True))
    except:
        logsOld = "<START LOG FILE> "
    ts0 = datetime.now().timestamp()
    logs = logsOld + "; " + ", ".join(str(log) for log in loglist) + ", ".join(timelog)
    timelog = []
    upload_data(s3= s3, logs=logs)
    ts1 = datetime.now().timestamp()
    timelog.append(f" Upload Time (Timelog): {str(ts1 - ts0)}")
    return


def load_file(s3, entries=None, logs=None, latesttx=None, history=None):
    if logs:
        return s3.get_object(Bucket="nerolationxi", Key="Logfile.txt")["Body"].read().decode("utf-8")
    if entries:
        return s3.get_object(Bucket="nerolationxi", Key="Entries.txt")["Body"].read().decode("utf-8")
    if latesttx:
        return s3.get_object(Bucket="nerolationxi", Key="LatestTx.txt")["Body"].read().decode("utf-8")
    if history:
        return s3.get_object(Bucket="nerolationxi", Key="History.txt")["Body"].read().decode("utf-8")


def create_log_list(*args):
    loglist = []
    for i in args:
        loglist.append(i)
    return loglist


def get_Date():
    dt = datetime.now()
    return dt.strftime("%d") + "/" + dt.strftime("%m") + "/" + dt.strftime("%y") + "," + dt.strftime("%X")


def create_sign_entry(addrHistory, newEntry):
    sig, addr, privkey, txHash, username = newEntry

    addrHistory.update({sig: {"sig": sig, "addr": addr, "privk": privkey, "txhash": txHash, "time":get_Date(), "username":username}})
    #print("addrHistory: ")
    #print(addrHistory)

    return json.dumps(addrHistory)



def initialize_s3():
    _s3 = boto3.client('s3')
    return _s3


def upload_data(s3, data=None, logs=None, latesttx=None, history=None):
    if data:
        s3.put_object(Bucket="nerolationxi", Key="Entries.txt", Body=data)
    if logs:
        s3.put_object(Bucket="nerolationxi", Key="Logfile.txt", Body=logs)
    if latesttx:
        s3.put_object(Bucket="nerolationxi", Key="LatestTx.txt", Body=latesttx)
    if history:
        s3.put_object(Bucket="nerolationxi", Key="History.txt", Body=history)


def safe_to_fetchlist(newentry):
    entryDict = {}
    s3 = initialize_s3()
    try:
        entryDict = json.loads(load_file(s3, latesttx=True))
        print("ENTRY DICT LOADED")
    except ClientError as ex:
        if ex.response['Error']['Code'] == 'NoSuchKey':
            print("NO SUCH KEY")
            upload_data(s3=s3, latesttx=json.dumps(newentry))
            return
        else:
            raise
    print("newEntry:")
    print(newentry)
    print("-------------")
    entryDict_3 = {**entryDict, **newentry}
    print(entryDict_3)
    upload_data(s3=s3, latesttx=json.dumps(entryDict_3))

    if newentry[list(newentry.keys())[0]]["tx"] != None:
        try:
            _, history = load_from_fetchlist(history=True)
            print("History returned")
        except:
            history = {}
        print(newentry)
        print("..............................")
        if list(newentry.keys())[0] in history.keys():
            i = 1
            while str(list(newentry.keys())[0])+ "_" + str(i) in history.keys():
                i += 1
            history[str(list(newentry.keys())[0]) + "_" + str(i) ]          =      newentry[list(newentry.keys())[0]]
            upload_data(s3=s3, history=json.dumps(history))

        else:
            upload_data(s3=s3, history=json.dumps({**history, **newentry}))


def load_from_fetchlist(history = False):
    s3 = initialize_s3()
    entryDict = {}
    try:
        entryDict = json.loads(load_file(s3, latesttx=True))
    except:
        upload_data(s3=s3, history=json.dumps({}))
    if history:
        history = json.loads(load_file(s3, history=True))
        return entryDict, history
    return entryDict


