#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description:
# Date: July 2020
# Update:
# Authors: Gaspard Lacave & Charles Prevot - Fortinet Paris
#

import logging
import sys
from logging.handlers import RotatingFileHandler
from configparser import ConfigParser

import upgrade_nothreads
import get_events

"""""" """""" """""" """""" """""" """
            logger
""" """""" """""" """""" """""" """"""
# création de l'objet logger qui va nous servir à écrire dans les logs
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger("bnp_upgrade")
formatter = logging.Formatter("%(asctime)s :: %(levelname)s :: %(message)s")
conf_file = ".ini"


def set_debug_level(str_level):
    if str_level == "DEBUG":
        return logging.DEBUG
    elif str_level == "WARNING":
        return logging.WARNING
    elif str_level == "INFO":
        return logging.INFO
    elif str_level == "ERROR":
        return logging.ERROR
    elif str_level == "FATAL":
        return logging.FATAL
    elif str_level == "WARN":
        return logging.WARN
    else:
        print("verbose level {} not supported, setting level to INFO".format(str_level))
        return logging.INFO


def main():
    # parse conf file
    parser = ConfigParser()
    parser.read(conf_file)

    if not parser.has_section("FORTIMANAGER") or not parser.has_section("GENERAL"):
        print(
            "Fatal error missing FORTIMANAGER or GENERAL section in {} configuration file".format(
                conf_file
            )
        )
    logger.setLevel(set_debug_level(parser.get("GENERAL", "verbose_log")))
    file_handler = RotatingFileHandler(
        parser.get("GENERAL", "log_file"), "a", 1000000, 1
    )
    file_handler.setLevel(set_debug_level(parser.get("GENERAL", "verbose_file")))
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # création d'un second handler qui va rediriger chaque écriture de log sur la console
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(set_debug_level(parser.get("GENERAL", "verbose_console")))
    logger.addHandler(stream_handler)
    upgrade_nothreads.logger = logger
    print(bool(parser.get("GENERAL", "automatic")))
    upgrade_nothreads.automatic = bool(parser.get("GENERAL", "automatic"))

    upgrade_nothreads.nb_max_threads = int(parser.get("GENERAL", "nb_thread"))
    upgrade_nothreads.target_version = str(parser.get("GENERAL", "target_version"))
    upgrade_nothreads.timeout = str(parser.get("GENERAL", "timeout"))

    # adom to upgrade
    section = "ADOM"
    adoms = []
    for options in parser.options(section):
        adoms.append(parser.get(section, options))

    # specific FortiGate to upgrade
    section = "FORTIGATES"
    fortigates = []

    section = "FORTIMANAGER"
    fmg_host = parser.get(section, "host")
    fmg_user = parser.get(section, "user")
    fmg_pass = parser.get(section, "pass")

    section = "FORTIANALYZER"
    faz_host = parser.get(section, "host")
    faz_user = parser.get(section, "user")
    faz_pass = parser.get(section, "pass")

    upgrade_nothreads.instanciation(
        adoms,
        fmg_host,
        fmg_user,
        fmg_pass,
        parser.get(section, "event_severity"),
        faz_host,
        faz_user,
        faz_pass,
    )


if __name__ == "__main__":
    main()
