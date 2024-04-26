from pyFMG import fortimgr
import ssl
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import threading
import sys
import snmp
import get_events

"""""" """""" """""" """""" """""" """
            logger
""" """""" """""" """""" """""" """"""
logger = None
automatic = False

target_version = ""
# name of the devices that failed the upgrade
failed_device = []

# list for the upgrade
device_same_update = []
threads_update = []

#
succeed_check = []
failed_check = []
cancelled_upgrade = []
#
upgraded_device = []

# number of upgrades that can be launched simultaneously
mutex = threading.Lock()
nb_max_threads = 0
timeout = 0


def kill_threads():
    for item in threads_update:
        item.kill()


def get_ip_device(fmg_instance, fgt_name):
    """
    Get the ip of the selected fortigate
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) name of the fortigate
    : return : (string) ip of the fortigate
    """
    ip = None
    # list_device = json.loads(str(fmg_instance.get('/dvmdb/device'.format(adom="root"))))
    dump_request = json.dumps(
        fmg_instance.get("/dvmdb/device/{name}".format(name=fgt_name)),
        sort_keys=True,
        indent=4,
    )
    # parse json
    list_request = json.loads(dump_request)
    for key in list_request[1]:
        if key == "ip":
            ip = list_request[1][key]
    if ip == None:
        logger.error("{n}: No ip found".format(n=fgt_name))
    return ip


def get_list_device_by_adom(fmg_instance, adom="root"):
    """
    Retreive the list of fortigate in the adom
    :param : (fmg_instance) the FortiManager connection instance
    :return : (list_device) the list of the fortigates registered
    """
    list_device = []
    # list_device = json.loads(str(fmg_instance.get('/dvmdb/device'.format(adom="root"))))
    dump_request = json.dumps(
        fmg_instance.get("/dvmdb/adom/{a}/device".format(a=adom)),
        sort_keys=True,
        indent=4,
    )
    # parse json
    list_request = json.loads(dump_request)
    for key in list_request[1]:
        for item, attribute in key.items():
            if item == "name":
                list_device.append(attribute)
    if list_device != None:
        logger.info("Adom {a}: Devices found".format(a=adom))
    return list_device


def get_output_ping(fmg_instance, fgt_name):
    """
    Retreive json return of the api call on the task
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted
    :return : (string) the output of the script
    """
    mutex.acquire()
    dump_request = json.dumps(
        fmg_instance.get("/dvmdb/script/log/list/device/{fgt}".format(fgt=fgt_name)),
        sort_keys=True,
        indent=4,
    )
    mutex.release()
    list_request = json.loads(dump_request)
    for key in list_request[1]:
        try:
            for item, attribute in key.items():
                if item == "content":
                    return attribute
        except:
            logger.error(
                "{n}: Output script of the ping. No content in json result of requests".format(
                    n=fgt_name
                )
            )
    return None


def get_output_script(fmg_instance, fgt_name):
    """
    Get the LAST output script executed on the device selected
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted by the request
    :return : (attribute) the log of the script
    """
    first = True
    mutex.acquire()
    dump_request = json.dumps(
        fmg_instance.get("/dvmdb/script/log/list/device/{fgt}".format(fgt=fgt_name)),
        sort_keys=True,
        indent=4,
    )
    mutex.release()
    list_request = json.loads(dump_request)
    for key in list_request[1]:
        if first == True:
            first = False
            for item, attribute in key.items():
                if item == "content":
                    list = attribute.split("\n")
                    status = {}
                    for item in list:
                        if "Version:" in item:
                            status["Version"] = item[9:]
                        if "License Status:" in item:
                            status["License"] = item[16:]
                        if "System time:" in item:
                            status["Time"] = item[13:]
                    return status


def get_status_fgt(fmg_instance, fgt_name, adom="root"):
    """
    Get the status by a script "Get system status" the device selected
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted by the request
    """
    # print(("{n}: Launching get status".format(n=fgt_name)))
    data = {
        "adom": adom,
        "scope": [{"name": fgt_name, "vdom": "root"}],
        "script": "get status",
    }
    mutex.acquire()
    response, task_obj = fmg_instance.execute("/dvmdb/script/execute", **data)
    mutex.release()
    if "task" in task_obj:
        taskid = task_obj.get("task")
        task = fmg_instance.track_task(taskid, 5)
    # if script went well go fetch the output of the script
    script_status = None
    if response == 0:
        script_status = get_output_script(fmg_instance, fgt_name)
    # print(("{n}: end get status".format(n=fgt_name)))
    return script_status


def ping_fmg(fmg_instance, fgt_name, adom="root"):
    """
    Ping the FortiManager by a script "Execute ping <ip address>" from the device selected
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted by the request
    """
    # print(("{n}: Launching ping".format(n=fgt_name)))
    data = {
        "adom": adom,
        "scope": [{"name": fgt_name, "vdom": "root"}],
        "script": "ping_fmg",
    }
    mutex.acquire()
    response, task_obj = fmg_instance.execute("/dvmdb/script/execute", **data)
    mutex.release()
    # check if the script is still executing
    if "task" in task_obj:
        taskid = task_obj.get("task")
        # wait for the end of the execution
        task = fmg_instance.track_task(taskid, 5)
    # if script went well go fetch the output of the script
    if response == 0:
        script_status = get_output_ping(fmg_instance, fgt_name)
        # print(("{n}: end ping".format(n=fgt_name)))
        if script_status == None:
            return False
        if "100% packet loss" in script_status or "Command fail" in script_status:
            logger.error("{n}: ping lost".format(n=fgt_name))
            return False
        else:
            logger.info("{n}: ping received".format(n=fgt_name))
            return True


def synchro_task(fmg_instance, device, adom):
    """
    Synchonize the connection between fortigate and fortimanager
    :param : (fmg_instance) the FortiManager connection instance
    :param : (device) the fortigate targeted
    :param : (adom) the adom targeted
    :return : (boolean) whether or the tunnel is up
    """
    success = False
    mutex.acquire()
    data = {"adom": "root", "device": device, "flags": ["create_task", "nonblocking"]}
    try:
        response, task_obj = fmg_instance.execute("/dvm/cmd/update/device", **data)
        taskid = task_obj.get("taskid")
        mutex.release()
        task = fmg_instance.track_task(taskid, 5, timeout=600)
        if "history" in task[1]:
            if "updatesuccess" in task[1]["history"][0]["detail"]:
                print("{f}: Success synchro".format(f=device))
                success = True
            else:
                print("{f}: Error at synchro".format(f=device))
    except fortimgr.FMGConnectionError:
        print("error connection")
    return success


def check_for_success_upgrade(fmg_instance, taskid):
    """
    Check for the completition of the upgrade
    :param : (fmg_instance) the FortiManager connection instance
    :param : (taskid) id
    :return : (Boolean) whether the upgrade has been completed or not
    """
    time.sleep(5)
    obj = fmg_instance.get("/task/task/{id}".format(id=taskid))

    success = ["Upgrade complete successfully", "reloadfin"]
    version = target_version

    if obj[1]["num_err"] == 0:
        logger.info("Upgrade complete successfully")
        return True
    else:
        for task in obj[1]["line"]:
            if task["detail"] != "Upgrade complete successfully":
                logger.error("{n}: Might Wrong success upgrade".format(n=task["name"]))
                name = task["name"].split("(")[0]
                failed_device.append(name)
        return False


def launch_upgrade_request(fmg_instance, fgt_names, data):
    """
    Launch the upgrade request for a list of fortigates
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted
    :return : (int) response code
    :return : (taskid) id of the task
    """
    time.sleep(3)
    try:
        response, task_obj = fmg_instance.execute("/um/image/upgrade", **data)
        # check if the script is still executing
        if "taskid" in task_obj:
            taskid = task_obj.get("taskid")
            logger.info("{n}: task id : {id}".format(id=taskid, n=fgt_names))
        return response, taskid
    except:
        logger.error("{n}: error on request for upgrade".format(n=fgt_names))
        return None, None


def reconnection(fmg_instance, fgt_names):
    """
    Try to reconnect recursively the fmg instance
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted
    :return : (Boolean) whether it is reconnected or not
    """
    logger.info("Trying to reconnect")
    time.sleep(10)
    try:
        fmg_instance.login()
        fmg_instance.lock_adom("root")
        logger.error("Reconnected")
    except fortimgr.FMGConnectionError:
        logger.error("error connection")
        if automatic == False:
            choice = input(
                "Do you want to try to reconnect again? [y or anything else for no]"
            )
            if choice == "y":
                logger.info("Retrying connection")
                reconnection(fmg_instance, fgt_names)
            else:
                # stop the upgrade for these fgt so add them the failed ones
                for item in fgt_names:
                    failed_device.append(item)
                return False
        else:
            reconnection(fmg_instance, fgt_names)
    return True


def track_task_by_id(fmg_instance, fgt_names, taskid):
    """
    Wait until the end of the upgrade of the fortigates
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted
    :param : (taskid) id
    """
    try:
        # wait for the end of the execution
        task = fmg_instance.track_task(taskid, 5, timeout=1800)
    except fortimgr.FMGConnectionError as ex:
        message = "task {n}: Connection with Fortimanager failed".format(n=taskid)
        logger.error(message)
        # try reconnection
        if reconnection(fmg_instance, fgt_names):
            # wait for the end of the execution
            track_task_by_id(fmg_instance, fgt_names, taskid)
    check_for_success_upgrade(fmg_instance, taskid)


def upgrade_task(fmg_instance, fgt_names, adom):
    """
    Ping the FortiManager by a script "Execute ping <ip address>" from the device selected
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_names) the list of fortigate targeted by the request
    """
    taskid = None
    list = []
    for item in fgt_names:
        list.append(
            {"name": "{n}".format(n=item)},
        )
    data = {
        "target start": 1,
        "adom": adom,
        "create_task": "enable",
        "device": list,
        "image": {"release": target_version},
    }
    try:
        response, taskid = launch_upgrade_request(fmg_instance, fgt_names, data)
    except fortimgr.FMGBaseException as ex:
        message = "{n}: exception of type {type} occurred. Arguments:\n{args}".format(
            n=fgt_names, type=type(ex).__name__, args=ex.args
        )
        logger.error(message)
        return
    except fortimgr.FMGConnectionError as ex:
        message = "{n}: exception of type {type} occurred. Arguments:\n{args}".format(
            n=fgt_names, type=type(ex).__name__, args=ex.args
        )
        logger.error(message)
        # try reconnection
        if reconnection(fmg_instance, fgt_names):
            # then relaunch the upgrade
            upgrade_task(fmg_instance, fgt_names, adom)
    if taskid != None:
        track_task_by_id(fmg_instance, fgt_names, taskid)
    else:
        logger.error(
            "{n}: upgrade task went wrong at launching of the request".format(
                n=fgt_names
            )
        )
        if automatic == False:
            choice = input("Do you want to retry the upgrade? [y or n]")
            if choice == "y":
                logger.info("Retrying the upgrade of the devices")
                upgrade_task(fmg_instance, fgt_names, adom)


def pre_check(fmg_instance, fgt_name, adom="root"):
    """
    Make all the pre check on the fortigate selected
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted by the request
    """
    sync = synchro_task(fmg_instance, fgt_name, adom)
    if sync:
        ip = get_ip_device(fmg_instance, fgt_name)
        status = get_status_fgt(fmg_instance, fgt_name, adom)
        if status != None:
            if "Version" in status:
                if target_version not in status["Version"]:
                    print("{n}: check ping".format(n=fgt_name))
                    if ping_fmg(fmg_instance, fgt_name, adom):
                        print("{n}: check snmp".format(n=fgt_name))
                        if snmp.compare_snmp_time(fgt_name, ip, 1):
                            print("{n}: end check".format(n=fgt_name))
                            mutex.acquire()
                            succeed_check.append(fgt_name)
                            mutex.release()
                        else:
                            name = str(fgt_name + ": SNMP pre-checks errors")
                            mutex.acquire()
                            failed_check.append(name)
                            mutex.release()
                    else:
                        name = str(fgt_name + ": Ping not receveived on pre-check")
                        mutex.acquire()
                        failed_check.append(name)
                        mutex.release()
                else:
                    name = str(
                        fgt_name
                        + ": Error of version (already in {v})".format(v=target_version)
                    )
                    mutex.acquire()
                    failed_check.append(name)
                    mutex.release()
            else:
                name = str(fgt_name + ": Problem of synchronization")
                mutex.acquire()
                failed_check.append(name)
                mutex.release()
        else:
            name = str(fgt_name + ": Problem of synchronization")
            mutex.acquire()
            failed_check.append(name)
            mutex.release()
    else:
        name = str(fgt_name + ": Problem of synchronization")
        mutex.acquire()
        failed_check.append(name)
        mutex.release()


def post_check(fmg_instance, fgt_name, adom="root"):
    """
    Make all the post check on the fortigate selected cheking also the good version of firmware
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_name) the fortigate targeted by the request
    """
    ip = get_ip_device(fmg_instance, fgt_name)
    status = get_status_fgt(fmg_instance, fgt_name, adom)
    if status != None:
        if "Version" in status:
            if target_version in status["Version"]:
                if ping_fmg(fmg_instance, fgt_name, adom):
                    if snmp.compare_snmp_time(fgt_name, ip, 2):
                        logger.info(
                            "{name}: Upgrade and post check completed".format(
                                name=fgt_name
                            )
                        )
                        mutex.acquire()
                        if fgt_name in failed_device:
                            failed_device.remove(name)
                        mutex.release()
                    else:
                        name = str(fgt_name + ": SNMP post-checks errors")
                        if fgt_name not in failed_device:
                            mutex.acquire()
                            failed_device.append(name)
                            mutex.release()
                else:
                    name = str(fgt_name + ": Ping not receveived on post-check")
                    if fgt_name not in failed_device:
                        mutex.acquire()
                        failed_device.append(name)
                        mutex.release()
            else:
                name = str(
                    fgt_name
                    + ": Error of version : {v})".format(
                        name=fgt_name, v=status["Version"]
                    )
                )
                if fgt_name not in failed_device:
                    mutex.acquire()
                    failed_device.append(name)
                    mutex.release()
        else:
            name = str(fgt_name + ": Problem of synchronization")
            if fgt_name not in failed_device:
                mutex.acquire()
                failed_device.append(name)
                mutex.release()
    else:
        name = str(fgt_name + ": Problem of synchronization")
        if fgt_name not in failed_device:
            mutex.acquire()
            failed_device.append(name)
            mutex.release()


def update_device(fmg_instance, fgt_list, adom):
    """
    Launch the pre,post checks and the upgrade and get all the failed and succeded upgrades
    :param : (fmg_instance) the FortiManager connection instance
    :param : (fgt_list) the fortigate targeted
    """
    for index, item in enumerate(fgt_list, start=0):
        logger.info("FGT Name : {n}".format(n=item))
        logger.info("{n}: Starting Pre check".format(n=item))
        threads_update.append(
            threading.Thread(
                target=pre_check,
                args=(
                    fmg_instance,
                    item,
                    adom,
                ),
                daemon=True,
            )
        )
        # time.sleep(2)
        threads_update[index].start()
    for j in range(len(threads_update)):
        threads_update[j].join()
    threads_update.clear()
    for item in failed_check:
        logger.error("{n}: Error on the pre checks".format(n=item))
        cancelled_upgrade.append(item)
    failed_check.clear()
    if succeed_check:
        upgrade_task(fmg_instance, succeed_check, adom)
    for index, item in enumerate(succeed_check, start=0):
        logger.info("{n}: Starting Post check".format(n=item))
        threads_update.append(
            threading.Thread(
                target=post_check,
                args=(
                    fmg_instance,
                    item,
                    adom,
                ),
                daemon=True,
            )
        )
        threads_update[index].start()
    for j in range(len(threads_update)):
        threads_update[j].join()
    threads_update.clear()
    succeed_check.clear()
    # check if you want to relaunch upgrade for the failed devices
    if failed_device:
        if automatic == False:
            choice = input(
                "{name}: Do you want to retry the upgrade? [y or n]".format(
                    name=failed_device
                )
            )
            if choice == "y":
                logger.info("Retrying the upgrade of the device")
                devices = []
                for fgt in failed_device:
                    name = fgt.split(":")[0]
                    devices.append(name)
                failed_device.clear()
                update_device(fmg_instance, devices, adom)
            else:
                for item in failed_device:
                    name = str(item + ": Failed during upgrade task. ")
                    cancelled_upgrade.append(name)
                failed_device.clear()
        else:
            for item in failed_device:
                name = str(item + ": Failed during upgrade task. ")
                cancelled_upgrade.append(name)
            failed_device.clear()


def instanciation(
    adom, fmg_host, fmg_user, fmg_pass, event_severity, faz_host, faz_user, faz_pass
):
    fmg_instance = fortimgr.FortiManager(fmg_host, fmg_user, fmg_pass)
    fmg_instance._use_ssl = False
    get_events.check_config(event_severity)
    faz_instance = get_events.login(faz_host, faz_user, faz_pass)
    try:
        fmg_instance.login()
        # fmg_instance.lock_adom("env1")
        for item in adom:
            if not get_events.get_events_by_adom(faz_instance, adom=item):
                devices = get_list_device_by_adom(fmg_instance, item)
                i = 0
                while i < len(devices):
                    device_same_update.clear()
                    for j in range(0, nb_max_threads):
                        if i < len(devices):
                            device_same_update.append(devices[i])
                            i += 1
                    update_device(fmg_instance, device_same_update, item)
        # fmg_instance.commit_changes("env1")
        # fmg_instance.unlock_adom("env1")
        fmg_instance.logout()
    except fortimgr.FMGConnectionError:
        logger.error("error connection")
        sys.exit()
    for item in cancelled_upgrade:
        logger.error("\n{n}: Couldn't be upgraded".format(n=item))
