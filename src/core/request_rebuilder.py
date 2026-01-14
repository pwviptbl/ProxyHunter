import json
from typing import Any, Dict
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

import requests

# Assuming RequestNode and InjectionPoint are dict-like objects
RequestNode = Dict[str, Any]
InjectionPoint = Dict[str, Any]


def _update_nested_dict(data: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
    """
    Updates a value in a nested dictionary based on a dot-separated path.
    """
    keys = path.split('.')
    current_level = data
    for key in keys[:-1]:
        current_level = current_level.setdefault(key, {})
    current_level[keys[-1]] = value
    return data


def rebuild_attack_request(
    request_node: RequestNode,
    injection_point: InjectionPoint,
    payload: str
) -> requests.PreparedRequest:
    """
    Rebuilds an HTTP request by injecting a payload into a specific injection point.

    Args:
        request_node: The request template.
        injection_point: The injection point details.
        payload: The payload to inject.

    Returns:
        A PreparedRequest object ready to be sent.
    """
    method = request_node['method']
    original_url = request_node['url']
    headers = json.loads(request_node['headers'])
    body = request_node['request_body_blob']

    location = injection_point['location']
    param_name = injection_point['parameter_name']
    original_value = injection_point['original_value']

    params = {}
    data = None
    json_data = None

    # Rebuild based on location
    parsed_url = urlparse(original_url)
    query_params = parse_qs(parsed_url.query)

    if location == 'QUERY':
        if param_name in query_params:
            # Find and replace only the specific original value
            for i, val in enumerate(query_params[param_name]):
                if val == original_value:
                    query_params[param_name][i] = payload
                    break
        new_query = urlencode(query_params, doseq=True)
        url = urlunparse(parsed_url._replace(query=new_query))
    else:
        url = original_url
        params = query_params

    if location == 'HEADER':
        if param_name in headers:
            headers[param_name] = headers[param_name].replace(original_value, payload, 1)

    if location == 'COOKIE':
        if 'Cookie' in headers and param_name in headers['Cookie']:
            # This is a simple replacement; a more robust solution would parse cookies properly
            cookie_string = headers['Cookie']
            cookie_to_replace = f"{param_name}={original_value}"
            new_cookie = f"{param_name}={payload}"
            headers['Cookie'] = cookie_string.replace(cookie_to_replace, new_cookie, 1)

    if location == 'BODY_FORM':
        form_data = parse_qs(body.decode('utf-8', errors='ignore'))
        if param_name in form_data:
            for i, val in enumerate(form_data[param_name]):
                if val == original_value:
                    form_data[param_name][i] = payload
                    break
        data = urlencode(form_data, doseq=True)
        # Ensure Content-Type is set for form data
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'


    if location == 'BODY_JSON':
        try:
            json_body = json.loads(body)
            json_data = _update_nested_dict(json_body, param_name, payload)
            data = None  # Unset raw data when using the json parameter
        except (json.JSONDecodeError, KeyError):
            # If body is not valid JSON or path is wrong, fallback to raw replacement
            data = body.replace(bytes(original_value, 'utf-8'), bytes(payload, 'utf-8'), 1)
            json_data = None

    # Reconstruct the request
    req = requests.Request(
        method=method,
        url=url,
        headers=headers,
        data=data,
        json=json_data
    )

    # Use a session to prepare the request, which handles content-length, etc.
    session = requests.Session()
    return session.prepare_request(req)
