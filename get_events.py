#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description:
# Date: July 2020
# Update:
# Authors: Gaspard Lacave & Charles Prevot - Fortinet Paris
#

import datetime
import json
import logging
import sys

import fortianalyzer

LOGGER = logging.getLogger("bnp_upgrade")
__SEVERITY__ = ["low", "medium", "high", "critical"]
SEVERITY = None


def _rank_severity(level):
    if level == "critical":
        return 3
    if level == "high":
        return 2
    if level == "medium":
        return 1
    if level == "low":
        return 0


def check_config(level):
    """
    Retreive config parameter of severity level, also check the value. #ZeroTrust
    :param : (level) config param to check. Severity level
    :return : None
    """
    global SEVERITY
    level = level.lower()  # lowercase
    for l in __SEVERITY__:
        if level == l:
            SEVERITY = level
            return
    LOGGER.error(
        'Error in config file: param "event_severity" = %s. Possible choices: low, medium, high, critical',
        level,
    )
    sys.exit(-2)


def login(host, user, pwd):
    faz = fortianalyzer.FortiAnalyzer(host, user, pwd, False, False)
    try:
        faz.login()
    except fortianalyzer.FMGConnectionError:
        LOGGER.error("error connection")
        sys.exit(-1)
    return faz


def get_events_by_adom(faz_instance, adom="root"):
    """
    Retreive events on FortiAnalyzer in the adom
    :param : (faz_instance) the FortiAnalyzer connection instance
    :param : (adom) the adom to look into
    :return : (list_device) the list of the fortigates registered
    """
    if not faz_instance:
        LOGGER.error("get_events_by_adom(): faz objet null")

    data = {
        "apiver": 3,
        "limit": 1000,
        "offset": 0,
        "time-range": {
            # last 24 hours timeframe
            "start": str(
                (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime(
                    "%Y-%m-%dT%H:%M:%S"
                )
            ),
            "end": str(datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")),
        },
    }

    res = faz_instance.get("/eventmgmt/adom/{a}/alerts".format(a=adom), **data)

    found = False
    for event in res:
        try:
            if _rank_severity(SEVERITY) <= _rank_severity(
                event["severity"]
            ):  # match our severity level
                found = True
                LOGGER.info(
                    'Found "%s" events in adom "%s". ABORDING UPGRADE.',
                    event["severity"],
                    adom,
                )
                break
        except KeyError:
            LOGGER.error("No severity element found")

    return found
