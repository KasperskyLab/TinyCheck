#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from app.utils import read_config
from app.classes.iocs import IOCs
from app.classes.whitelist import WhiteList
from app.classes.misp import MISP

import requests
import json
import urllib3
import time
from multiprocessing import Process

"""
    This file is parsing the watchers present
    in the configuration file. This in order to get
    automatically new iocs / elements from remote
    sources without user interaction.
"""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def watch_iocs():
    """
        Retrieve IOCs from the remote URLs defined in config/watchers.
        For each IOC, add it to the DB.
    """

    # Retrieve the URLs from the configuration
    urls = read_config(("watchers", "iocs"))
    watchers = [{"url": url, "status": False} for url in urls]

    while True:
        for w in watchers:
            if w["status"] == False:
                iocs = IOCs()
                iocs_list = []
                to_delete = []
                try:
                    res = requests.get(w["url"], verify=False)
                    if res.status_code == 200:
                        content = json.loads(res.content)
                        iocs_list = content["iocs"] if "iocs" in content else []
                        to_delete = content["to_delete"] if "to_delete" in content else []
                    else:
                        w["status"] = False
                except:
                    w["status"] = False

                for ioc in iocs_list:
                    try:
                        iocs.add(ioc["type"], ioc["tag"],
                                 ioc["tlp"], ioc["value"], "watcher")
                        w["status"] = True
                    except:
                        continue

                for ioc in to_delete:
                    try:
                        iocs.delete_by_value(ioc["value"])
                        w["status"] = True
                    except:
                        continue

        # If at least one URL haven't be parsed, let's retry in 1min.
        if False in [w["status"] for w in watchers]:
            time.sleep(60)
        else:
            break


def watch_whitelists():
    """
        Retrieve whitelist elements from the remote URLs
        defined in config/watchers. For each (new ?) element,
        add it to the DB.
    """

    urls = read_config(("watchers", "whitelists"))
    watchers = [{"url": url, "status": False} for url in urls]

    while True:
        for w in watchers:
            if w["status"] == False:
                whitelist = WhiteList()
                elements = []
                to_delete = []
                try:
                    res = requests.get(w["url"], verify=False)
                    if res.status_code == 200:
                        content = json.loads(res.content)
                        elements = content["elements"] if "elements" in content else []
                        to_delete = content["to_delete"] if "to_delete" in content else []
                    else:
                        w["status"] = False
                except:
                    w["status"] = False

                for elem in elements:
                    try:
                        whitelist.add(elem["type"], elem["element"], "watcher")
                        w["status"] = True
                    except:
                        continue

                for elem in to_delete:
                    try:
                        whitelist.delete_by_value(elem["element"])
                        w["status"] = True
                    except:
                        continue

        if False in [w["status"] for w in watchers]:
            time.sleep(60)
        else:
            break


def watch_misp():
    """
        Retrieve IOCs from misp instances. Each new element is
        tested and then added to the database.
    """
    iocs, misp = IOCs(), MISP()
    instances = list(misp.get_instances())

    while instances:
        for i, ist in enumerate(instances):
            status = misp.test_instance(ist["url"],
                                        ist["apikey"],
                                        ist["verifycert"])
            if status:
                for ioc in misp.get_iocs(ist["id"]):
                    iocs.add(ioc["type"], ioc["tag"], ioc["tlp"],
                             ioc["value"], "misp-{}".format(ist["id"]))
                misp.update_sync(ist["id"])
                instances.pop(i)
        if instances: time.sleep(60)


p1 = Process(target=watch_iocs)
p2 = Process(target=watch_whitelists)
p3 = Process(target=watch_misp)

p1.start()
p2.start()
p3.start()
