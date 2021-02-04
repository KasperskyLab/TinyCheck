#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from utils import get_iocs, get_apname, get_device, get_config
import time
import os
import subprocess as sp
import re
import json
import sys


class SuricataEngine():

    def __init__(self, capture_directory):

        self.wdir = capture_directory
        self.alerts = []
        self.rules_file = "/tmp/rules.rules"
        self.pcap_path = os.path.join(self.wdir, "capture.pcap")
        self.rules = [r[0] for r in get_iocs(
            "snort")] + self.generate_contextual_alerts()

        self.userlang = get_config(("frontend", "user_lang"))

        # Load template language
        if not re.match("^[a-z]{2,3}$", self.userlang):
            self.userlang = "en"
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "lang/{}.json".format(self.userlang))) as f:
            self.template = json.load(f)["alerts"]

    def start_suricata(self):
        """
            Launch suricata against the capture.pcap file.
            :return: nothing.
        """

        # Generate the rule file an launch suricata.
        if self.generate_rule_file():
            sp.Popen(["suricata", "-S", self.rules_file, "-r",
                      self.pcap_path, "-l", "/tmp/"]).wait()

        # Let's parse the log file.
        for line in open("/tmp/fast.log", "r").readlines():
            if "[**]" in line:
                s = line.split("[**]")[1].strip()
                m = re.search(
                    r"\[\d+\:(?P<sid>\d+)\:(?P<rev>\d+)\] (?P<title>[ -~]+)", s)
                self.alerts.append({"title": self.template["SNORT-01"]["title"].format(m.group('title')),
                                    "description": self.template["SNORT-01"]["description"],
                                    "level": "High",
                                    "id": "SNORT-01"})
        # Remove fast.log
        os.remove("/tmp/fast.log")

    def generate_rule_file(self):
        """
            Generate the rules file passed to suricata.
            :return: bool if operation succeed.
        """
        try:
            with open(self.rules_file, "w+") as f:
                f.write("\n".join(self.rules))
                return True
        except:
            return False

    def generate_contextual_alerts(self):
        """
            Generate contextual alerts related to the current
            ssid or the device itself.
        """
        apname = get_apname()
        device = get_device(self.wdir.split("/")[-1])
        rules = []

        # Devices names to be whitelisted (can appear in UA of HTTP requests. So FP high alerts)
        device_names = ["iphone", "ipad", "android", "samsung", "galaxy",
                        "huawei", "oneplus", "oppo", "pixel", "xiaomi", "realme", "chrome",
                        "safari"]

        if apname and device:
            # See if the AP name is sent in clear text over the internet.
            if len(apname) >= 5:
                rules.append(
                    'alert tcp {} any -> $EXTERNAL_NET any (content:"{}"; msg:"WiFi name sent in clear text"; sid:10000101; rev:001;)'.format(device["ip_address"], apname))
                rules.append(
                    'alert udp {} any -> $EXTERNAL_NET any (content:"{}"; msg:"WiFi name sent in clear text"; sid:10000102; rev:001;)'.format(device["ip_address"], apname))

            # See if the device name is sent in clear text over the internet.
            if len(device["name"]) >= 5 and device["name"].lower() not in device_names:
                rules.append('alert tcp {} any -> $EXTERNAL_NET any (content:"{}"; msg:"Device name sent in clear text"; sid:10000103; rev:001;)'.format(
                    device["ip_address"], device["name"]))
                rules.append('alert udp {} any -> $EXTERNAL_NET any (content:"{}"; msg:"Device name sent in clear text"; sid:10000104; rev:001;)'.format(
                    device["ip_address"], device["name"]))

        return rules

    def get_alerts(self):
        return [dict(t) for t in {tuple(d.items()) for d in self.alerts}]
