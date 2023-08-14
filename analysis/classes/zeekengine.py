
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from classes.parsezeeklogs import ParseZeekLogs
from netaddr import IPNetwork, IPAddress
from utils import get_iocs, get_config, get_whitelist
from datetime import datetime
import subprocess as sp
import json
import pydig
import os
import re
import sys
import whois


class ZeekEngine(object):

    def __init__(self, capture_directory):
        self.working_dir = capture_directory
        self.alerts = []
        self.conns = []
        self.ssl = []
        self.http = []
        self.dns = []
        self.files = []
        self.whitelist = []

        # Get analysis and userlang configuration
        self.heuristics_analysis = get_config(("analysis", "heuristics"))
        self.iocs_analysis = get_config(("analysis", "iocs"))
        self.whitelist_analysis = get_config(("analysis", "whitelist"))
        self.active_analysis = get_config(("analysis", "active"))
        self.userlang = get_config(("frontend", "user_lang"))

        # Retreive IOCs.
        if self.iocs_analysis:
            self.bl_cidrs = [[IPNetwork(cidr[0]), cidr[1]]
                             for cidr in get_iocs("cidr")]
            self.bl_hosts = get_iocs("ip4addr") + get_iocs("ip6addr")
            self.bl_domains = get_iocs("domain")
            self.bl_freedns = get_iocs("freedns")
            self.bl_nameservers = get_iocs("ns")
            self.bl_tlds = get_iocs("tld")

        # Retreive whitelisted items.
        if self.whitelist_analysis:
            self.wl_cidrs = [IPNetwork(cidr) for cidr in get_whitelist("cidr")]
            self.wl_hosts = get_whitelist("ip4addr") + get_whitelist("ip6addr")
            self.wl_domains = get_whitelist("domain")

        # Load template language
        if not re.match("^[a-z]{2,3}$", self.userlang):
            self.userlang = "en"
        with open(os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "locales/{}.json".format(self.userlang))) as f:
            self.template = json.load(f)["alerts"]

    def fill_dns(self, dir):
        """
            Fill the DNS resolutions thanks to the dns.log.
            :return: nothing - all resolutions appended to self.dns.
        """
        if os.path.isfile(os.path.join(dir, "dns.log")):
            for record in ParseZeekLogs(os.path.join(dir, "dns.log"), output_format="json", safe_headers=False):
                if record is not None:
                    if record["qtype_name"] in ["A", "AAAA"]:
                        d = {"domain": record["query"],
                             "answers": record["answers"].split(",")}
                        if d not in self.dns:
                            self.dns.append(d)

    def netflow_check(self, dir):
        """
            Enrich and check the netflow from the conn.log against whitelist and IOCs.
            :return: nothing - all stuff appended to self.alerts
        """
        max_ports = get_config(("analysis", "max_ports"))
        http_default_port = get_config(("analysis", "http_default_port"))

        # Get the netflow from conn.log.
        if os.path.isfile(os.path.join(dir, "conn.log")):
            for record in ParseZeekLogs(os.path.join(dir, "conn.log"), output_format="json", safe_headers=False):
                if record is not None:
                    c = {"ip_dst": record["id.resp_h"],
                         "proto": record["proto"],
                         "port_dst": record["id.resp_p"],
                         "service": record["service"],
                         "alert_tiggered": False}
                    if c not in self.conns:
                        self.conns.append(c)

        # Let's add some dns resolutions.
        for c in self.conns:
            c["resolution"] = self.resolve(c["ip_dst"])

        # Order the conns list by the resolution field.
        self.conns = sorted(self.conns, key=lambda c: c["resolution"])

        # Check for whitelisted assets, if any, delete the record.
        if self.whitelist_analysis:

            for i, c in enumerate(self.conns):
                if c["ip_dst"] in [ip for ip in self.wl_hosts]:
                    self.whitelist.append(self.conns[i])
                    self.conns[i] = False
                elif c["resolution"] in self.wl_domains:
                    self.whitelist.append(self.conns[i])
                    self.conns[i] = False
                elif True in [c["resolution"].endswith("." + dom) for dom in self.wl_domains]:
                    self.whitelist.append(self.conns[i])
                    self.conns[i] = False
                elif True in [IPAddress(c["ip_dst"]) in cidr for cidr in self.wl_cidrs]:
                    self.whitelist.append(self.conns[i])
                    self.conns[i] = False

            # Let's delete whitelisted connections.
            self.conns = list(filter(lambda c: c != False, self.conns))

        if self.heuristics_analysis:
            for c in self.conns:
                # Check for UDP / ICMP (strange from a smartphone.)
                if c["proto"] in ["UDP", "ICMP"]:
                    c["alert_tiggered"] = True
                    self.alerts.append({"title": self.template["PROTO-01"]["title"].format(c["proto"].upper(), c["resolution"]),
                                        "description": self.template["PROTO-01"]["description"].format(c["proto"].upper(), c["resolution"]),
                                        "host":  c["resolution"],
                                        "level": "Moderate",
                                        "id": "PROTO-01"})
                # Check for use of ports over 1024.
                if c["port_dst"] >= max_ports:
                    c["alert_tiggered"] = True
                    self.alerts.append({"title": self.template["PROTO-02"]["title"].format(c["proto"].upper(), c["resolution"], max_ports),
                                        "description": self.template["PROTO-02"]["description"].format(c["proto"].upper(), c["resolution"], c["port_dst"]),
                                        "host":  c["resolution"],
                                        "level": "Low",
                                        "id": "PROTO-02"})
                # Check for use of HTTP.
                if c["service"] == "http" and c["port_dst"] == http_default_port:
                    c["alert_tiggered"] = True
                    self.alerts.append({"title": self.template["PROTO-03"]["title"].format(c["resolution"]),
                                        "description": self.template["PROTO-03"]["description"].format(c["resolution"]),
                                        "host":  c["resolution"],
                                        "level": "Low",
                                        "id": "PROTO-03"})

                # Check for use of HTTP on a non standard port.
                if c["service"] == "http" and c["port_dst"] != http_default_port:
                    c["alert_tiggered"] = True
                    self.alerts.append({"title": self.template["PROTO-04"]["title"].format(c["resolution"], c["port_dst"]),
                                        "description": self.template["PROTO-04"]["description"].format(c["resolution"], c["port_dst"]),
                                        "host":  c["resolution"],
                                        "level": "Moderate",
                                        "id": "PROTO-04"})
                # Check for non-resolved IP address.
                if c["ip_dst"] == c["resolution"]:
                    c["alert_tiggered"] = True
                    self.alerts.append({"title": self.template["PROTO-05"]["title"].format(c["ip_dst"]),
                                        "description": self.template["PROTO-05"]["description"].format(c["ip_dst"]),
                                        "host": c["ip_dst"],
                                        "level": "Low",
                                        "id": "PROTO-05"})

        if self.iocs_analysis:

            for c in self.conns:
                # Check for blacklisted IP address.
                for host in self.bl_hosts:
                    if c["ip_dst"] == host[0]:
                        c["alert_tiggered"] = True
                        self.alerts.append({"title": self.template["IOC-01"]["title"].format(c["resolution"], c["ip_dst"], host[1].upper()),
                                            "description": self.template["IOC-01"]["description"].format(c["ip_dst"]),
                                            "host": c["resolution"],
                                            "level": "High",
                                            "id": "IOC-01"})
                        break
                # Check for blacklisted CIDR.
                for cidr in self.bl_cidrs:
                    if IPAddress(c["ip_dst"]) in cidr[0]:
                        c["alert_tiggered"] = True
                        self.alerts.append({"title": self.template["IOC-02"]["title"].format(c["resolution"], cidr[0], cidr[1].upper()),
                                            "description": self.template["IOC-02"]["description"].format(c["resolution"]),
                                            "host": c["resolution"],
                                            "level": "Moderate",
                                            "id": "IOC-02"})
                # Check for blacklisted domain.
                for domain in self.bl_domains:
                    if c["resolution"].endswith(domain[0]):
                        if domain[1] != "tracker":
                            c["alert_tiggered"] = True
                            self.alerts.append({"title": self.template["IOC-03"]["title"].format(c["resolution"], domain[1].upper()),
                                                "description": self.template["IOC-03"]["description"].format(c["resolution"]),
                                                "host": c["resolution"],
                                                "level": "High",
                                                "id": "IOC-03"})
                        else:
                            c["alert_tiggered"] = True
                            self.alerts.append({"title": self.template["IOC-04"]["title"].format(c["resolution"], domain[1].upper()),
                                                "description": self.template["IOC-04"]["description"].format(c["resolution"]),
                                                "host": c["resolution"],
                                                "level": "Moderate",
                                                "id": "IOC-04"})
                # Check for blacklisted FreeDNS.
                for domain in self.bl_freedns:
                    if c["resolution"].endswith("." + domain[0]):
                        c["alert_tiggered"] = True
                        self.alerts.append({"title": self.template["IOC-05"]["title"].format(c["resolution"]),
                                            "description": self.template["IOC-05"]["description"].format(c["resolution"]),
                                            "host": c["resolution"],
                                            "level": "Moderate",
                                            "id": "IOC-05"})

                # Check for suspect tlds.
                for tld in self.bl_tlds:
                    if c["resolution"].endswith(tld[0]):
                        c["alert_tiggered"] = True
                        self.alerts.append({"title": self.template["IOC-06"]["title"].format(c["resolution"]),
                                            "description": self.template["IOC-06"]["description"].format(c["resolution"], tld[0]),
                                            "host": c["resolution"],
                                            "level": "Low",
                                            "id": "IOC-06"})
        if self.active_analysis:
            for c in self.conns:
                try:  # Domain nameservers check.
                    name_servers = pydig.query(c["resolution"], "NS")
                    if len(name_servers):
                        for ns in self.bl_nameservers:
                            if name_servers[0].endswith(".{}.".format(ns[0])):
                                c["alert_tiggered"] = True
                                self.alerts.append({"title": self.template["ACT-01"]["title"].format(c["resolution"], name_servers[0]),
                                                    "description": self.template["ACT-01"]["description"].format(c["resolution"]),
                                                    "host": c["resolution"],
                                                    "level": "Moderate",
                                                    "id": "ACT-01"})
                except:
                    pass

                try:  # Domain history check.

                    whois_record = whois.whois(c["resolution"])
                    creation_date = whois_record.creation_date if type(
                        whois_record.creation_date) is not list else whois_record.creation_date[0]
                    creation_days = abs((datetime.now() - creation_date).days)
                    if creation_days < 365:
                        c["alert_tiggered"] = True
                        self.alerts.append({"title": self.template["ACT-02"]["title"].format(c["resolution"], creation_days),
                                            "description": self.template["ACT-02"]["description"].format(c["resolution"]),
                                            "host": c["resolution"],
                                            "level": "Moderate",
                                            "id": "ACT-02"})

                except:
                    pass

    def files_check(self, dir):
        """
            Check on the files.log:
                * Check certificates sha1
                * [todo] Check possible binary data or APKs?
            :return: nothing - all stuff appended to self.alerts
        """

        if not self.iocs_analysis:
            return

        bl_certs = get_iocs("sha1cert")

        if os.path.isfile(os.path.join(dir, "files.log")):
            for record in ParseZeekLogs(os.path.join(dir, "files.log"), output_format="json", safe_headers=False):
                if record is not None:
                    f = {"filename": record["filename"],
                         "ip_src": record["id.orig_h"],
                         "ip_dst": record["id.resp_h"],
                         "mime_type": record["mime_type"],
                         "sha1": record["sha1"]}
                    if f not in self.files:
                        self.files.append(f)

        for f in self.files:
            if f["mime_type"] == "application/x-x509-user-cert":
                for cert in bl_certs:  # Check for blacklisted certificate.
                    if f["sha1"] == cert[0]:
                        host = self.resolve(f["ip_src"])
                        self.alerts.append({"title": self.template["IOC-07"]["title"].format(cert[1].upper(), host),
                                            "description": self.template["IOC-07"]["description"].format(f["sha1"], host),
                                            "host": host,
                                            "level": "High",
                                            "id": "IOC-07"})

    def http_check(self, dir):
        """
            Check on the http.log:
                * Blacklisted domain/tld from the Host header field.
            Can be used when no DNS query have been done during the session (already cached by the device.)
            :return: nothing - all stuff appended to self.alerts
        """

        if os.path.isfile(os.path.join(dir, "http.log")):
            for record in ParseZeekLogs(os.path.join(dir, "http.log"), output_format="json", safe_headers=False):
                if record is not None:
                    c = {"host": record['host']}
                    if c not in self.http:
                        self.http.append(c)

        if self.iocs_analysis:
            for c in self.http:

                # If we already know the host form DNS, let's continue.
                if c["host"] in [r["domain"] for r in self.dns]:
                    continue

                # Check for blacklisted domain.
                for h in self.bl_domains:
                    if h[1] != "tracker":
                        if c["host"].endswith(h[0]):
                            self.alerts.append({"title": self.template["IOC-08"]["title"].format(c["host"], h[1].upper()),
                                                "description": self.template["IOC-08"]["description"].format(c["host"]),
                                                "host": c["host"],
                                                "level": "High",
                                                "id": "IOC-08"})
                # Check for freedns.
                for h in self.bl_freedns:
                    if c["host"].endswith(h[0]):
                        self.alerts.append({"title": self.template["IOC-09"]["title"].format(c["host"]),
                                            "description": self.template["IOC-09"]["description"].format(c["host"]),
                                            "host": c["host"],
                                            "level": "Moderate",
                                            "id": "IOC-09"})
                # Check for fancy TLD.
                for h in self.bl_tlds:
                    if c["host"].endswith(h[0]):
                        self.alerts.append({"title": self.template["IOC-10"]["title"].format(c["host"]),
                                            "description": self.template["IOC-10"]["description"].format(c["host"], h[0]),
                                            "host": c["host"],
                                            "level": "Low",
                                            "id": "IOC-10"})

    def ssl_check(self, dir):
        """
            Check on the ssl.log:
                * SSL connections which doesn't use the 443.
                * "Free" certificate issuer (taken from the config).
                * Self-signed certificates.
                * Blacklisted domain in the CN
            :return: nothing - all stuff appended to self.alerts
        """
        ssl_default_ports = get_config(("analysis", "ssl_default_ports"))
        free_issuers = get_config(("analysis", "free_issuers"))

        if os.path.isfile(os.path.join(dir, "ssl.log")):
            for record in ParseZeekLogs(os.path.join(dir, "ssl.log"), output_format="json", safe_headers=False):
                if record is not None:
                    c = {"host": record['id.resp_h'],
                         "port": record['id.resp_p'],
                         "issuer": record["issuer"] if "issuer" in record else "",
                         "validation_status": record["validation_status"],
                         "cn": record["server_name"] if "server_name" in record else ""}
                    if c not in self.ssl:
                        self.ssl.append(c)

        if self.heuristics_analysis:
            for cert in self.ssl:
                host = self.resolve(cert["host"])

                # If the associated host has not whitelisted, check the cert.
                for c in self.conns:
                    if host in c["resolution"]:
                        # Check for non generic SSL port.
                        if cert["port"] not in ssl_default_ports:
                            c["alert_tiggered"] = True
                            self.alerts.append({"title": self.template["SSL-01"]["title"].format(cert["port"], host),
                                                "description": self.template["SSL-01"]["description"].format(host),
                                                "host": host,
                                                "level": "Moderate",
                                                "id": "SSL-01"})
                        # Check Free SSL certificates.
                        if cert["issuer"] in free_issuers:
                            c["alert_tiggered"] = True
                            self.alerts.append({"title": self.template["SSL-02"]["title"].format(host),
                                                "description": self.template["SSL-02"]["description"],
                                                "host": host,
                                                "level": "Moderate",
                                                "id": "SSL-02"})
                        # Check for self-signed certificates.
                        if cert["validation_status"] == "self signed certificate in certificate chain":
                            c["alert_tiggered"] = True
                            self.alerts.append({"title": self.template["SSL-03"]["title"].format(host),
                                                "description": self.template["SSL-03"]["description"].format(host),
                                                "host": host,
                                                "level": "Moderate",
                                                "id": "SSL-03"})

        if self.iocs_analysis:
            for cert in self.ssl:
                # Check if the domain in the certificate haven't been blacklisted
                # This check can be good if the domain has already been cached by
                # the device so it wont appear in self.dns.

                if any([cert["cn"].endswith(r["domain"]) for r in self.dns]):
                    continue

                for domain in self.bl_domains:
                    if domain[1] != "tracker":
                        if cert["cn"].endswith(domain[0]):
                            self.alerts.append({"title": self.template["SSL-04"]["title"].format(domain[0], domain[1].upper()),
                                                "description": self.template["SSL-04"]["description"].format(domain[0]),
                                                "host": domain[0],
                                                "level": "High",
                                                "id": "SSL-04"})

    def alerts_check(self):
        """
            Leverage an advice to the user based on the trigered hosts
            :return: nothing - all generated alerts appended to self.alerts
        """
        hosts = {}

        for alert in [dict(t) for t in {tuple(d.items()) for d in self.alerts}]:
            if alert["host"] not in hosts:
                hosts[alert["host"]] = 1
            else:
                hosts[alert["host"]] += 1

        for host, nb in hosts.items():
            if nb >= get_config(("analysis", "max_alerts")):
                self.alerts.append({"title": self.template["ADV-01"]["title"].format(host),
                                    "description": self.template["ADV-01"]["description"].format(host, nb),
                                    "host": host,
                                    "level": "Moderate",
                                    "id": "ADV-01"})

    def resolve(self, ip_addr):
        """
            A simple method to retreive DNS names from IP addresses
            in order to replace them in alerts.

            :return: String - DNS record or IP Address.
        """
        for record in self.dns:
            if ip_addr in record["answers"]:
                return record["domain"]
        return ip_addr

    def start_zeek(self):
        """
            Start zeek and check the logs.
        """
        sp.Popen("cd {} && /opt/zeek/bin/zeek -Cr capture.pcap protocols/ssl/validate-certs".format(
            self.working_dir), shell=True).wait()
        sp.Popen("cd {} && mv *.log assets/".format(self.working_dir),
                 shell=True).wait()
        self.fill_dns(self.working_dir + "/assets/")
        self.netflow_check(self.working_dir + "/assets/")
        self.ssl_check(self.working_dir + "/assets/")
        self.http_check(self.working_dir + "/assets/")
        self.files_check(self.working_dir + "/assets/")
        self.alerts_check()

    def retrieve_alerts(self):
        """
            Retrieve alerts.
            :return: list - a list of alerts wihout duplicates.
        """
        return [dict(t) for t in {tuple(d.items()) for d in self.alerts}]

    def retrieve_whitelist(self):
        """
            Retrieve whitelisted elements.
            :return: list - a list of whitelisted elements wihout duplicates.
        """
        return [dict(t) for t in {tuple(d.items()) for d in self.whitelist}]

    def retrieve_conns(self):
        """
            Retrieve not whitelisted elements.
            :return: list - a list of non-whitelisted elements wihout duplicates.
        """
        return self.conns
