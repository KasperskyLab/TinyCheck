#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import datetime
import yaml
import sys
import json
import os
from functools import reduce

# I'm not going to use an ORM for that.
parent = os.path.split(os.path.dirname(os.path.abspath(sys.argv[0])))[0]
conn = sqlite3.connect(os.path.join(parent, "tinycheck.sqlite3"))
cursor = conn.cursor()


def get_iocs(ioc_type):
    """
        Get a list of IOCs specified by their type.
        :return: list of IOCs
    """
    cursor.execute(
        "SELECT value, tag FROM iocs WHERE type = ? ORDER BY value", (ioc_type,))
    res = cursor.fetchall()
    return [[r[0], r[1]] for r in res] if res is not None else []


def get_whitelist(elem_type):
    """
        Get a list of whitelisted elements specified by their type.
        :return: list of elements
    """
    cursor.execute(
        "SELECT element FROM whitelist WHERE type = ? ORDER BY element", (elem_type,))
    res = cursor.fetchall()
    return [r[0] for r in res] if res is not None else []


def get_config(path):
    """
        Read a value from the configuration
        :return: value (it can be any type)
    """
    config = yaml.load(open(os.path.join(parent, "config.yaml"),
                            "r"), Loader=yaml.SafeLoader)
    return reduce(dict.get, path, config)


def get_device(token):
    """
        Read the device configuration from device.json file.
        :return: dict - the device configuration
    """
    try:
        with open("/tmp/{}/device.json".format(token), "r") as f:
            return json.load(f)
    except:
        pass


def get_apname():
    """
        Read the current name of the Access Point from
        the hostapd configuration file
        :return: str - the AP name
    """
    try:
        with open("/tmp/hostapd.conf", "r") as f:
            for l in f.readlines():
                if "ssid=" in l:
                    return l.replace("ssid=", "").strip()
    except:
        pass
