#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Blueprint, jsonify, Response
from app.decorators import require_header_token, require_get_token
from app.classes.whitelist import WhiteList
import json

whitelist_bp = Blueprint("whitelist", __name__)
whitelist = WhiteList()


@whitelist_bp.route('/add/<elem_type>/<path:elem_value>', methods=['GET'])
@require_header_token
def add(elem_type, elem_value):
    """
        Parse and add an element to be whitelisted.
        :return: status of the operation in JSON
    """
    source = "backend"
    res = whitelist.add(elem_type, elem_value, source)
    return jsonify(res)


@whitelist_bp.route('/delete/<elem_id>', methods=['GET'])
@require_header_token
def delete(elem_id):
    """
        Delete an element by its id in the database.
        :return: status of the operation in JSON
    """
    res = whitelist.delete(elem_id)
    return jsonify(res)


@whitelist_bp.route('/search/<element>', methods=['GET'])
@require_header_token
def search(element):
    """
        Search elements in the database.
        :return: potential results in JSON.
    """
    res = whitelist.search(element)
    return jsonify({"results": list(res)})


@whitelist_bp.route('/get/types')
@require_header_token
def get_types():
    """
        Retrieve a list of whitelisted elements types.
        :return: list of types in JSON.
    """
    res = whitelist.get_types()
    return jsonify({"types": list(res)})


@whitelist_bp.route('/export')
@require_get_token
def get_all():
    """
        Retreive a list of all elements.
        :return: list of elements in JSON.
    """
    res = whitelist.get_all()
    return Response(json.dumps({"elements": list(res)}),
                    mimetype='application/json',
                    headers={'Content-Disposition': 'attachment;filename=whitelist-export.json'})
