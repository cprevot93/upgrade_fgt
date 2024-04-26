import configparser
from pysnmp.hlapi import *
from pysnmp.smi.view import MibViewController
import time

config = configparser.ConfigParser()
config.read(".ini")


def get_snmp_values(fgt_name, ip):
    """
    Requests the fortigate with OIDs predefined on the .ini file
    :param : (fgt_name) name of the fortigate
    :param : (ip) ip of the fortigate
    :return : (dictionnary) values of the OIDs targeted
    """
    snmp_values = {}
    for item in config["OID"]:
        # print("{i}: {oid}".format(i=item,oid=config['OID'][item]))
        snmp_values[item] = []
        for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
            SnmpEngine(),
            CommunityData("BNPp2o!9_RO", mpModel=1),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(config["OID"][item])),
            lookupMib=False,
            lexicographicMode=False,
        ):
            if errorIndication or errorStatus:
                print("Error")
                print(errorIndication or errorStatus)
                break
            else:
                for varBind in varBinds:
                    snmp_values[item].append(int(varBind[1]))
                    # print(' = '.join([x.prettyPrint() for x in varBind]))
        threshold = "limit_" + item
        # print("{n}: {t}".format(t=config['OID_LIMIT'][threshold],n=threshold))
        # print("\n")
    return snmp_values


def compare_snmp_time(fgt_name, ip, period=5):
    """
    Compare between two moments the snmp values of the fortigate selected
    :param : (fgt_name) name of the fortigate
    :param : (ip) ip of the fortigate
    :param : (period) period between the two requests (by default 5s)
    :return : (boolean) true if the checks are good
    """
    good_health = True
    values_t0 = get_snmp_values(fgt_name, ip)
    limit_cpu = int(config["OID_LIMIT"]["limit_fgSysCpuUsage"])
    limit_mem = int(config["OID_LIMIT"]["limit_fgSysMemUsage"])
    limit_ses_count = int(config["OID_LIMIT"]["limit_fgSysSesCount"])
    limit_ses_rate = int(config["OID_LIMIT"]["limit_fgSysSesRate1"])
    for item in values_t0:
        if item == "ifoperstatus":
            # if the interfaces are up at t and t+1
            for index in range(len(values_t0[item])):
                if values_t0[item][index] != 1:
                    print("{i}: {n}".format(i=item, n=values_t0[item][index]))
                    good_health = False
        elif item == "fgsyscpuusage":
            if values_t0[item][0] >= limit_cpu:
                print(
                    "{i}: Limit reached of cpu usage".format(
                        i=item, n=values_t0[item][0]
                    )
                )
                good_health = False
        elif item == "fgsyssesrate1":
            if values_t0[item][0] <= limit_ses_rate:
                print("{i}: Rate session to low".format(i=item, n=values_t0[item][0]))
                good_health = False
        elif item == "fgsysmemusage":
            if values_t0[item][0] >= limit_mem:
                print(
                    "{i}: Limit of memory usage reached".format(
                        i=item, n=values_t0[item][0]
                    )
                )
                good_health = False
        elif item == "fgsyssescount":
            if values_t0[item][0] <= limit_ses_count:
                print("{i}: Not enougth sessions".format(i=item, n=values_t0[item][0]))
                good_health = False
    return good_health
