#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import sys
import io
import os
import re
import hashlib
from functools import reduce
from flask import send_file


class Config(object):
    def __init__(self):
        self.dir = "/".join(sys.path[0].split("/")[:-2])
        return None

    def read_config(self, path):
        """
            Read a single value from the configuration
            :return: value (it can be any type)
        """
        config = yaml.load(
            open(os.path.join(self.dir, "config.yaml"), "r"), Loader=yaml.SafeLoader)
        return reduce(dict.get, path, config)

    def export_config(self):
        """
            Export the configuration
            :return: dict (configuration content)
        """
        config = yaml.load(
            open(os.path.join(self.dir, "config.yaml"), "r"), Loader=yaml.SafeLoader)
        config["ifaces_in"] = self.get_ifaces_in()
        config["ifaces_out"] = self.get_ifaces_out()
        return config

    def write_config(self, cat, key, value):
        """
            Write a new value in the configuration
            :return: bool, operation status
        """

        config = yaml.load(
            open(os.path.join(self.dir, "config.yaml"), "r"), Loader=yaml.SafeLoader)

        # Some checks prior configuration changes.
        if cat not in config:
            return {"status": False,
                    "message": "Wrong category specified"}

        if key not in config[cat]:
            return {"status": False,
                    "message": "Wrong key specified"}

        # Changes for network interfaces.
        if cat == "network" and key in ["in", "out"]:
            if re.match("^(wlan[0-9]|wl[a-z0-9]{20})$", value):
                if key == "in":
                    self.edit_configuration_files(value)
                    config[cat][key] = value
                if key == "out":
                    config[cat][key] = value
            elif re.match("^(eth[0-9]|en[a-z0-9]{20})$", value) and key == "out":
                config[cat][key] = value
            else:
                return {"status": False,
                        "message": "Wrong value specified"}

        # Changes for network SSIDs.
        elif cat == "network" and key == "ssids":
            ssids = list(set(value.split("|"))) if "|" in value else [value]
            if ssids:
                config[cat][key] = ssids

        # Changes for watchers.
        elif cat == "watchers" and key in ["iocs", "whitelists"]:
            urls = []
            values = list(set(value.split("|"))) if "|" in value else [value]
            for value in values:  # Preventing SSRF based on watchers URLs.
                if "https://raw.githubusercontent.com" in value[0:33]:
                    urls.append(value)
            if urls:
                config[cat][key] = urls

        # Changes for backend password.
        elif cat == "backend" and key == "password":
            config[cat][key] = self.make_password(value)

        # Changes for anything not specified.
        # Warning: can break your config if you play with it (eg. arrays, ints & bools).
        else:
            if isinstance(value, bool):
                config[cat][key] = value
            elif len(value):
                config[cat][key] = value

        with open(os.path.join(self.dir, "config.yaml"), "w") as yaml_file:
            yaml_file.write(yaml.dump(config, default_flow_style=False))
            return {"status": True,
                    "message": "Configuration updated"}

    def make_password(self, clear_text):
        """
            Make a simple password hash (without salt)
        """
        return hashlib.sha256(clear_text.encode()).hexdigest()

    def export_db(self):
        """
            Export the database.
            :return: send_file (the database)
        """
        with open(os.path.join(self.dir, "tinycheck.sqlite3"), "rb") as f:
            return send_file(
                io.BytesIO(f.read()),
                mimetype="application/octet-stream",
                as_attachment=True,
                attachment_filename='tinycheck-export-db.sqlite')

    def get_ifaces_in(self):
        """
            List the Wireless interfaces on the box
            which can be used as Access Points.
            :return: list of the interfaces
        """
        try:
            return [i for i in os.listdir("/sys/class/net/") if i.startswith("wl")]
        except:
            return ["No wireless interface"]

    def get_ifaces_out(self):
        """
            List the network interfaces on the box
            which can be used to access to Internet.
            :return: list of the interfaces
        """
        try:
            return [i for i in os.listdir("/sys/class/net/") if i.startswith(("wl", "et"))]
        except:
            return ["No network interfaces"]

    def edit_configuration_files(self, iface):
        """
            Edit the DNSMasq and DHCPCD configuration files
            :return: nothing.
        """
        try:
            if re.match("^(wlan[0-9]|wlx[a-f0-9]{12})$", iface):
                # Edit of DHCPD.conf
                with open("/etc/dhcpcd.conf", 'r') as file:
                    content = file.readlines()
                for i, line in enumerate(content):
                    if line.startswith("interface"):
                        content[i] = "interface {}\n".format(iface)
                with open("/etc/dhcpcd.conf", 'w') as file:
                    file.writelines(content)

                # Edit of DNSMASQ.conf
                with open("/etc/dnsmasq.conf", 'r') as file:
                    content = file.readlines()
                for i, line in enumerate(content):
                    if line.startswith("interface"):
                        content[i] = "interface={}\n".format(iface)
                with open("/etc/dnsmasq.conf", 'w') as file:
                    file.writelines(content)
        except:
            pass
