#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess as sp
import json
import sys
import re
import os


class Analysis(object):

    def __init__(self, token):
        self.token = token if re.match(r"[A-F0-9]{8}", token) else None

    def start(self):
        """
            Start an analysis of the captured communication by lauching
            analysis.py with the capture token as a paramater.

            :return: dict containing the analysis status
        """

        if self.token is not None:
            parent = "/".join(sys.path[0].split("/")[:-2])
            sp.Popen(
                [sys.executable, "{}/analysis/analysis.py".format(parent), "-f", "/tmp/{}".format(self.token)])
            return {"status": True,
                    "message": "Analysis started",
                    "token": self.token}
        else:
            return {"status": False,
                    "message": "Bad token provided",
                    "token": "null"}

    def get_report(self):
        """
            Generate a small json report of the analysis
            containing the alerts and the device properties.

            :return: dict containing the report or error message.
        """

        device, alerts, pcap = {}, {}, {}

        # Getting device configuration.
        if os.path.isfile("/tmp/{}/assets/device.json".format(self.token)):
            with open("/tmp/{}/assets/device.json".format(self.token), "r") as f:
                device = json.load(f)

        # Getting pcap infos.
        if os.path.isfile("/tmp/{}/assets/capinfos.json".format(self.token)):
            with open("/tmp/{}/assets/capinfos.json".format(self.token), "r") as f:
                pcap = json.load(f)

        # Getting alerts configuration.
        if os.path.isfile("/tmp/{}/assets/alerts.json".format(self.token)):
            with open("/tmp/{}/assets/alerts.json".format(self.token), "r") as f:
                alerts = json.load(f)

        if device != {} and alerts != {}:
            return {"alerts": alerts,
                    "device": device,
                    "pcap": pcap}
        else:
            return {"message": "No report yet"}
