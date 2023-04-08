#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import sys
from flask import Blueprint, jsonify
from app.classes.analysis import Analysis
import subprocess as sp

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route("/start/<token>", methods=["GET"])
def api_start_analysis(token):
    """
        Start an analysis
    """
    return jsonify(Analysis(token).start())


@analysis_bp.route("/report/<token>", methods=["GET"])
def api_report_analysis(token):
    """
        Get the report of an analysis
    """
    return jsonify(Analysis(token).get_report())
