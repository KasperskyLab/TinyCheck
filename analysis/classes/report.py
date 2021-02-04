import weasyprint
import os
import json
import hashlib
import re
import sys

from weasyprint import HTML
from pathlib import Path
from datetime import datetime
from utils import get_config


class Report(object):

    def __init__(self, capture_directory):
        self.capture_directory = capture_directory
        self.alerts = self.read_json(os.path.join(
            capture_directory, "assets/alerts.json"))
        self.whitelist = self.read_json(os.path.join(
            capture_directory, "assets/whitelist.json"))
        self.conns = self.read_json(os.path.join(
            capture_directory, "assets/conns.json"))
        self.device = self.read_json(os.path.join(
            capture_directory, "assets/device.json"))
        self.capinfos = self.read_json(os.path.join(
            capture_directory, "assets/capinfos.json"))
        try:
            with open(os.path.join(self.capture_directory, "capture.pcap"), "rb") as f:
                self.capture_sha1 = hashlib.sha1(f.read()).hexdigest()
        except:
            self.capture_sha1 = "N/A"

        self.userlang = get_config(("frontend", "user_lang"))

        # Load template language
        if not re.match("^[a-z]{2}$", self.userlang):
            self.userlang = "en"
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "lang/{}.json".format(self.userlang)))as f:
            self.template = json.load(f)["report"]

    def read_json(self, json_path):
        """
            Read and convert a JSON file.
            :return: array or dict.
        """
        with open(json_path, "r") as json_file:
            return json.load(json_file)

    def generate_report(self):
        """
            Generate the full report in PDF
            :return: nothing
        """
        content = self.generate_page_header()
        content += self.generate_header()
        content += self.generate_warning()
        content += self.generate_alerts()
        content += self.generate_suspect_conns_block()
        content += self.generate_uncat_conns_block()
        content += self.generate_whitelist_block()

        htmldoc = HTML(string=content, base_url="").write_pdf()
        Path(os.path.join(self.capture_directory,
                          "report.pdf")).write_bytes(htmldoc)

    def generate_warning(self):
        """
            Generate the warning message.
            :return: str
        """
        if len(self.alerts["high"]):
            msg = "<div class=\"warning high\">"
            msg += self.template["high_msg"].format(
                self.nb_translate(len(self.alerts["high"])))
            msg += "</div>"
            return msg
        elif len(self.alerts["moderate"]):
            msg = "<div class=\"warning moderate\">"
            msg += self.template["moderate_msg"].format(
                self.nb_translate(len(self.alerts["moderate"])))
            msg += "</div>"
            return msg
        elif len(self.alerts["low"]):
            msg = "<div class=\"warning low\">"
            msg += self.template["low_msg"].format(
                self.nb_translate(len(self.alerts["low"])))
            msg += "</div>"
            return msg
        else:
            msg = "<div class=\"warning low\">"
            msg += self.template["none_msg"]
            msg += "</div>"
            return msg

    def nb_translate(self, nb):
        """
            Translate a number in a string.
            :return: str
        """
        a = self.template["numbers"]
        return a[nb-1] if nb <= 9 else str(nb)

    def generate_suspect_conns_block(self):
        """
            Generate the table of the network non-whitelisted communications.
            :return: string
        """

        if not len([c for c in self.conns if c["alert_tiggered"] == True]):
            return ""

        title = "<h2>{}</h2>".format(self.template["suspect_title"])
        table = "<table>"
        table += "    <thead>"
        table += "        <tr>"
        table += "             <th>{}</th>".format(self.template["protocol"])
        table += "             <th>{}</th>".format(self.template["domain"])
        table += "             <th>{}</th>".format(self.template["dst_ip"])
        table += "             <th>{}</th>".format(self.template["dst_port"])
        table += "        </tr>"
        table += "    </thead>"
        table += "<tbody>"

        for rec in self.conns:
            if rec["alert_tiggered"] == True:
                table += "<tr>"
                table += "<td>{}</td>".format(rec["proto"].upper())
                table += "<td>{}</td>".format(rec["resolution"]
                                              if rec["resolution"] != rec["ip_dst"] else "--")
                table += "<td>{}</td>".format(rec["ip_dst"])
                table += "<td>{}</td>".format(rec["port_dst"])
                table += "</tr>"
        table += "</tbody></table>"
        return title + table

    def generate_uncat_conns_block(self):
        """
            Generate the table of the network non-whitelisted communications.
            :return: string
        """
        if not len([c for c in self.conns if c["alert_tiggered"] == False]):
            return ""

        title = "<h2>{}</h2>".format(self.template["uncat_title"])
        table = "<table>"
        table += "    <thead>"
        table += "        <tr>"
        table += "             <th>{}</th>".format(self.template["protocol"])
        table += "             <th>{}</th>".format(self.template["domain"])
        table += "             <th>{}</th>".format(self.template["dst_ip"])
        table += "             <th>{}</th>".format(self.template["dst_port"])
        table += "        </tr>"
        table += "    </thead>"
        table += "<tbody>"

        for rec in self.conns:
            if rec["alert_tiggered"] == False:
                table += "<tr>"
                table += "<td>{}</td>".format(rec["proto"].upper())
                table += "<td>{}</td>".format(rec["resolution"]
                                              if rec["resolution"] != rec["ip_dst"] else "--")
                table += "<td>{}</td>".format(rec["ip_dst"])
                table += "<td>{}</td>".format(rec["port_dst"])
                table += "</tr>"
        table += "</tbody></table>"
        return title + table

    def generate_whitelist_block(self):
        """
            Generate the table of the whitelisted communications.
            :return: string
        """
        if not len(self.whitelist):
            return ""

        title = "<h2>{}</h2>".format(self.template["whitelist_title"])
        table = "<table>"
        table += "    <thead>"
        table += "        <tr>"
        table += "             <th>{}</th>".format(self.template["protocol"])
        table += "             <th>{}</th>".format(self.template["domain"])
        table += "             <th>{}</th>".format(self.template["dst_ip"])
        table += "             <th>{}</th>".format(self.template["dst_port"])
        table += "        </tr>"
        table += "    </thead>"
        table += "<tbody>"

        for rec in sorted(self.whitelist, key=lambda k: k['resolution']):
            table += "<tr>"
            table += "<td>{}</td>".format(rec["proto"].upper())
            table += "<td>{}</td>".format(rec["resolution"]
                                          if rec["resolution"] != rec["ip_dst"] else "--")
            table += "<td>{}</td>".format(rec["ip_dst"])
            table += "<td>{}</td>".format(rec["port_dst"])
            table += "</tr>"
        table += "</tbody></table>"
        return title + table

    def generate_header(self):
        """
            Generate the report header with context data.
            :return: string
        """
        header = "<div class=\"header\">"
        header += "<div class=\"logo\"></div>"
        header += "<p><br /><strong>{}: {}</strong><br />".format(self.template["device_name"],
                                                                  self.device["name"])
        header += "{}: {}<br />".format(self.template["device_mac"],
                                        self.device["mac_address"])
        header += "{} {}<br />".format(self.template["report_generated_on"],
                                       datetime.now().strftime("%d/%m/%Y - %H:%M:%S"))
        header += "{}: {}s<br />".format(self.template["capture_duration"],
                                         self.capinfos["Capture duration"])
        header += "{}: {}<br />".format(self.template["packets_number"],
                                        self.capinfos["Number of packets"])
        header += "{}: {}<br />".format(
            self.template["capture_sha1"], self.capture_sha1)
        header += "</p>"
        header += "</div>"
        return header

    def generate_alerts(self):
        """
            Generate the alerts.
            :return: string
        """
        alerts = "<ul class=\"alerts\">"
        for alert in self.alerts["high"]:
            alerts += "<li class =\"alert\">"
            alerts += "<span class=\"high-label\">High</span>"
            alerts += "<span class=\"alert-id\">{}</span>".format(alert["id"])
            alerts += "<div class = \"alert-body\">"
            alerts += "<span class=\"title\">{}</span>".format(alert["title"])
            alerts += "<p class=\"description\">{}</p>".format(
                alert["description"])
            alerts += "</div>"
            alerts += "</li>"

        for alert in self.alerts["moderate"]:
            alerts += "<li class =\"alert\">"
            alerts += "<span class=\"moderate-label\">moderate</span>"
            alerts += "<span class=\"alert-id\">{}</span>".format(alert["id"])
            alerts += "<div class = \"alert-body\">"
            alerts += "<span class=\"title\">{}</span>".format(alert["title"])
            alerts += "<p class=\"description\">{}</p>".format(
                alert["description"])
            alerts += "</div>"
            alerts += "</li>"
        for alert in self.alerts["low"]:
            alerts += "<li class =\"alert\">"
            alerts += "<span class=\"low-label\">low</span>"
            alerts += "<span class=\"alert-id\">{}</span>".format(alert["id"])
            alerts += "<div class = \"alert-body\">"
            alerts += "<span class=\"title\">{}</span>".format(alert["title"])
            alerts += "<p class=\"description\">{}</p>".format(
                alert["description"])
            alerts += "</div>"
            alerts += "</li>"

        alerts += "</ul>"
        return alerts

    def generate_page_footer(self):
        """
            Generate the html footer.
            :return: string
        """
        return "</body></html>"

    def generate_page_header(self):
        """
            Generate the html header.
            :return: string
        """
        return """<html
                    <head>
                        <style>
                            * {
                                font-family: Arial, Helvetica, sans-serif;
                            }

                            h2 {
                                padding-top: 30px;
                                font-weight: 400;
                                font-size: 18px;
                            }

                            td {
                                width: auto;
                                padding: 10px;
                            }

                            table {
                                background: #FFF;
                                border: 2px solid #FAFAFA;
                                border-radius: 5px;
                                border-collapse: separate;
                                border-spacing: 0px;
                                width: 100%;
                                font-size: 12px;
                            }

                            p {
                                font-size: 13px;
                            }

                            thead tr th {
                                border-bottom: 1px solid #CCC;
                                border-collapse: separate;
                                border-spacing: 5px 5px;
                                background-color: #FFF;
                                padding: 10px;
                                text-align: left;
                            }

                            tbody tr#first td {
                                border-top: 3px solid #4d4d4d;
                                border-collapse: separate;
                                border-spacing: 5px 5px;
                            }

                            tr:nth-of-type(odd) {
                                background-color: #fafafa;
                            }

                            .logo {
                                background-image: url("data:image/png;base64,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");
                                width: 200px;
                                height: 60px;
                                background-size: cover;
                                position: absolute;
                                right: 0px;
                            }

                            .warning {
                                padding: 10px;
                                text-align: center;
                                border-radius: 5px;
                                color: #FFF;
                                margin-top: 40px;
                                margin-bottom: 40px;
                                font-weight:900;
                            }

                            .high {
                                background-color: #F44336;
                            }

                            .moderate {
                                background-color: #ff7e33eb;
                            }

                            .low {
                                background-color: #4fce0eb8;
                            }

                            ul {
                                list-style: none;
                                margin: 0;
                                padding: 0;
                            }

                            .alert {
                                margin-top: 15px;
                            }

                            .alert-body {
                                background-color: #FFF;
                                list-style: none;
                                padding: 10px;
                                border-radius: 5px;
                                border: 1px solid #EEE;
                                margin-top: 3px;
                            }

                            .alert-body>.title {
                                display: block;
                                padding: 5px 5px 5px 10px;
                                font-size: 13px;
                            }

                            .high-label {
                                background-color: #F44336;
                                padding: 5px;
                                text-transform: uppercase;
                                font-size: 10px;
                                font-weight: bold;
                                border-radius: 3px 0px 0px 0px;
                                margin: 0px;
                                color: #FFF;
                                margin-left: 10px;
                            }

                            .moderate-label {
                                background-color: #ff7e33eb;
                                padding: 5px;
                                text-transform: uppercase;
                                font-size: 10px;
                                font-weight: bold;
                                border-radius: 3px 0px 0px 0px;
                                margin: 0px;
                                color: #FFF;
                                margin-left: 10px;
                            }

                            .low-label {
                                background-color: #4fce0eb8;
                                padding: 5px;
                                text-transform: uppercase;
                                font-size: 10px;
                                font-weight: bold;
                                border-radius: 3px 0px 0px 0px;
                                margin: 0px;
                                color: #FFF;
                                margin-left: 10px;
                            }

                            .description {
                                margin: 0;
                                padding: 10px;
                                color:#333;
                                font-size:12px;
                            }

                            ul {
                                list-style: none;
                                margin: 0;
                                padding: 0;
                            }

                            .alert-id {
                                background-color: #636363;
                                padding: 5px;
                                text-transform: uppercase;
                                font-size: 10px;
                                font-weight: bold;
                                border-radius: 0px 3px 0px 0px;
                                margin: 0px;
                                color: #FFF;
                                margin-right: 10px;
                            }
                 
                            .header>p {
                                font-size:12px;
                            }
                            @page {
                                @top-center { 
                                    content: "REPORT_HEADER - Page " counter(page) " / " counter(pages) ".";
                                    font-size:12px;
                                    color:#CCC;
                                }
                                @bottom-center { 
                                    content: REPORT_FOOTER;
                                    font-size:12px;  
                                    color:#CCC;
                                }
                            }   
                        </style>
                    </head>
                    <body>""".replace("REPORT_HEADER", "{} {}".format(self.template["report_for_the_capture"], self.capture_sha1)).replace("REPORT_FOOTER", self.template["report_footer"])
