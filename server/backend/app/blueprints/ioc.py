#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, Response, request
from app.decorators import require_header_token, require_get_token
from app.classes.iocs import IOCs

import json
from urllib.parse import unquote

ioc_bp = Blueprint("ioc", __name__)
ioc = IOCs()


@ioc_bp.route('/add/<ioc_type>/<ioc_tag>/<ioc_tlp>/<path:ioc_value>', methods=['GET'])
@require_header_token
def add(ioc_type, ioc_tag, ioc_tlp, ioc_value):
    """
        Parse and add an IOC to the database.
        :return: status of the operation in JSON
    """
    source = "backend"
    if ioc_type == "snort":
        ioc_value = unquote("/".join(request.full_path.split("/")[7:]))
    res = IOCs.add(ioc_type, ioc_tag, ioc_tlp, ioc_value, source)
    return jsonify(res)


@ioc_bp.route('/add_post', methods=['POST'])
@require_header_token
def add_post():
    """
        Parse and add an IOC to the database using the post method.
        :return: status of the operation in JSON
    """

    data = json.loads(request.data)
    ioc = data["data"]["ioc"]
    res = IOCs.add(ioc["ioc_type"], ioc["ioc_tag"], ioc["ioc_tlp"], ioc["ioc_value"], ioc["ioc_source"])
    return jsonify(res)


@ioc_bp.route('/delete/<ioc_id>', methods=['GET'])
@require_header_token
def delete(ioc_id):
    """
        Delete an IOC by its id in the database.
        :return: status of the operation in JSON
    """
    res = IOCs.delete(ioc_id)
    return jsonify(res)


@ioc_bp.route('/search/<term>', methods=['GET'])
@require_header_token
def search(term):
    """
        Search IOCs in the database.
        :return: potential results in JSON.
    """
    res = IOCs.search(term)
    return jsonify({"results": list(res)})


@ioc_bp.route('/get/types')
@require_header_token
def get_types():
    """
        Retreive a list of IOCs types.
        :return: list of types in JSON.
    """
    res = IOCs.get_types()
    return jsonify({"types": list(res)})


@ioc_bp.route('/get/tags')
@require_header_token
def get_tags():
    """
        Retreive a list of IOCs tags.
        :return: list of types in JSON.
    """
    res = IOCs.get_tags()
    return jsonify({"tags": list(res)})


@ioc_bp.route('/export')
@require_get_token
def get_all():
    """
        Retreive a list of all IOCs.
        :return: list of iocs in JSON.
    """
    res = IOCs.get_all()
    return Response(json.dumps({"iocs": list(res)}),
                    mimetype='application/json',
                    headers={'Content-Disposition': 'attachment;filename=iocs-export.json'})
