#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from classes.zeekengine import ZeekEngine
from classes.suricataengine import SuricataEngine
from classes.report import Report
from multiprocessing import Process, Manager
import sys
import re
import json
import os

"""
    This file is called by the frontend but the analysis
    can be done in standalone by just submitting the directory
    containing a capture.pcap file.
"""


def analyze(capture_directory,frontend=False):
    if os.path.isdir(capture_directory):

        manager = Manager()
        alerts = manager.dict()

        def zeekengine(alerts):
            zeek = ZeekEngine(capture_directory)
            zeek.start_zeek()
            alerts["zeek"] = zeek.retrieve_alerts()

            if not os.path.isdir(os.path.join(capture_directory, "assets")):
                os.mkdir(os.path.join(capture_directory, "assets"))
            # whitelist.json writing.
            with open(os.path.join(capture_directory, "assets/whitelist.json"), "w") as f:
                f.write(json.dumps(zeek.retrieve_whitelist(),
                                   indent=4, separators=(',', ': ')))

            # conns.json writing.
            with open(os.path.join(capture_directory, "assets/conns.json"), "w") as f:
                f.write(json.dumps(zeek.retrieve_conns(),
                                   indent=4, separators=(',', ': ')))

        def snortengine(alerts):
            suricata = SuricataEngine(capture_directory)
            suricata.start_suricata()
            alerts["suricata"] = suricata.get_alerts()

        # Start the engines.
        p1 = Process(target=zeekengine, args=(alerts,))
        p2 = Process(target=snortengine, args=(alerts,))
        p1.start()
        p2.start()

        # Wait to their end.
        p1.join()
        p2.join()

        # Some formating and alerts.json writing.
        with open(os.path.join(capture_directory, "assets/alerts.json"), "w") as f:
            report = {"high": [], "moderate": [], "low": []}
            for alert in (alerts["zeek"] + alerts["suricata"]):
                if alert["level"] == "High":
                    report["high"].append(alert)
                if alert["level"] == "Moderate":
                    report["moderate"].append(alert)
                if alert["level"] == "Low":
                    report["low"].append(alert)
            f.write(json.dumps(report, indent=4, separators=(',', ': ')))

        # Generate the report
        report = Report(capture_directory,frontend)
        report.generate_report()

    else:
        print("The directory doesn't exist.")


def usage():
    print("""Usage: python analysis.py [capture_directory]
     where [capture_directory] is a directory containing a capture.pcap file
     analysis.py -f starts the analysis in frontend mode intended to be called by the TinyCheck frontend.""")


if __name__ == "__main__":
    if len(sys.argv) == 2: #called manually without frontend
        analyze(sys.argv[1], False)
    elif len(sys.argv) == 3:
        if(sys.argv[1]) == "-f": #frontend mode
            analyze(sys.argv[2], True)
        else:
            usage()

    else:
        usage()



