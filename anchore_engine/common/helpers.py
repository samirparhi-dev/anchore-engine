"""
Common message types and marshalling helper functions
"""
import copy
import time

import base64
import json
import stat

import anchore_engine.configuration.localconfig
from anchore_engine import utils
from anchore_engine.subsys import logger
from anchore_engine.common import os_package_types


def make_image_content_response(content_type, content_data):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    all_content_types = localconfig.get("image_content_types", []) + localconfig.get(
        "image_metadata_types", []
    )

    if content_type not in all_content_types:
        logger.warn(
            "input content_type (%s) not supported (%s)",
            content_type,
            all_content_types,
        )
        return []

    if not content_data:
        logger.warn("empty content data given to format - returning empty result")
        return []

    builder = CONTENT_RESPONSE_BUILDER_DISPATCH.get(
        content_type, _build_default_response
    )
    return builder(content_data)


def _build_os_response(content_data):
    response = []
    for package_name, package_info in content_data.items():
        el = {}
        try:
            el["package"] = package_name
            for field in ["license", "origin", "size", "type", "version"]:
                if field in package_info:
                    el[field] = package_info[field]
                else:
                    el[field] = None

                if field == "license":
                    if el[field]:
                        el["licenses"] = el[field].split(" ")
                    else:
                        el["licenses"] = []

            # Special formatting for os packages. Ensure that if there is a release field it is added to the version string
            if package_info.get("type", "").lower() in os_package_types:
                v = package_info.get("version", None)
                r = package_info.get("release", None)
                if (v and r) and (v.lower() != "n/a") and r.lower() != "n/a":
                    el["version"] = "{}-{}".format(v, r)
        except:
            continue
        response.append(el)
    return response


def _build_npm_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = "NPM"
            el["location"] = package
            el["version"] = content_data[package]["versions"][0]
            el["origin"] = ",".join(content_data[package]["origins"]) or "Unknown"
            el["license"] = " ".join(content_data[package]["lics"]) or "Unknown"
            el["licenses"] = content_data[package]["lics"] or ["Unknown"]
        except:
            continue
        response.append(el)
    return response


def _build_gem_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = "GEM"
            el["location"] = package
            el["version"] = content_data[package]["versions"][0]
            el["origin"] = ",".join(content_data[package]["origins"]) or "Unknown"
            el["license"] = " ".join(content_data[package]["lics"]) or "Unknown"
            el["licenses"] = content_data[package]["lics"] or ["Unknown"]
        except:
            continue
        response.append(el)
    return response


def _build_python_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = "PYTHON"
            el["location"] = content_data[package]["location"]
            el["version"] = content_data[package]["version"]
            el["origin"] = content_data[package]["origin"] or "Unknown"
            el["license"] = content_data[package]["license"] or "Unknown"
            el["licenses"] = content_data[package]["license"].split(" ") or ["Unknown"]
        except:
            continue
        response.append(el)
    return response


def _build_java_response(content_data):
    response = []
    for package in list(content_data.keys()):
        el = {}
        try:
            el["package"] = content_data[package]["name"]
            el["type"] = content_data[package]["type"].upper()
            el["location"] = content_data[package]["location"]
            el["specification-version"] = content_data[package]["specification-version"]
            el["implementation-version"] = content_data[package][
                "implementation-version"
            ]
            el["maven-version"] = content_data[package]["maven-version"]
            el["origin"] = content_data[package]["origin"] or "Unknown"
        except:
            continue
        response.append(el)
    return response


def _build_files_response(content_data):
    response = []
    elmap = {
        "linkdst": "linkdest",
        "size": "size",
        "mode": "mode",
        "sha256": "sha256",
        "type": "type",
        "uid": "uid",
        "gid": "gid",
    }
    for filename in list(content_data.keys()):
        el = {}
        try:
            el["filename"] = filename
            for elkey in list(elmap.keys()):
                try:
                    el[elmap[elkey]] = content_data[filename][elkey]
                except:
                    el[elmap[elkey]] = None

            # special formatting
            el["mode"] = format(stat.S_IMODE(el["mode"]), "05o")
            if el["sha256"] == "DIRECTORY_OR_OTHER":
                el["sha256"] = None
        except:
            continue
        response.append(el)
    return response


def _safe_base64_encode(data_provider):
    try:
        return utils.ensure_str(base64.encodebytes(utils.ensure_bytes(data_provider())))
    except Exception as err:
        logger.warn("could not base64 encode content - exception: %s", err)
    return ""


def _build_docker_history_response(content_data):
    return _safe_base64_encode(lambda: json.dumps(content_data))


def _build_dockerfile_response(content_data):
    return _safe_base64_encode(lambda: content_data)


def _build_manifest_response(content_data):
    return _safe_base64_encode(lambda: content_data)


def _build_default_response(content_data):
    response = []
    try:
        for package in list(content_data.keys()):
            el = {}
            try:
                el["package"] = content_data[package]["name"]
                el["type"] = content_data[package]["type"].upper()
                el["location"] = (
                    content_data[package].get("location", None) or "Unknown"
                )
                el["version"] = content_data[package].get("version", None) or "Unknown"
                el["origin"] = content_data[package].get("origin", None) or "Unknown"
                el["license"] = content_data[package].get("license", None) or "Unknown"
                el["licenses"] = (
                    content_data[package].get("license", "Unknown").split(" ")
                )
            except Exception as err:
                continue
            response.append(el)
        if not response:
            raise Exception("empty return list after generic element parse")
    except Exception as err:
        logger.debug(
            "couldn't parse any generic package elements, returning raw content_data - exception: %s",
            err,
        )
        response = content_data

    return response


def _build_malware_response(content_data):
    return content_data


CONTENT_RESPONSE_BUILDER_DISPATCH = {
    "os": _build_os_response,
    "npm": _build_npm_response,
    "gem": _build_gem_response,
    "python": _build_python_response,
    "java": _build_java_response,
    "files": _build_files_response,
    "docker_history": _build_docker_history_response,
    "dockerfile": _build_dockerfile_response,
    "manifest": _build_manifest_response,
    "malware": _build_malware_response,
}


def make_response_error(errmsg, in_httpcode=None, details=None):
    if details is None:
        details = {}
    if not in_httpcode:
        httpcode = 500
    else:
        httpcode = in_httpcode

    msg = str(errmsg)

    ret = {"message": msg, "httpcode": int(httpcode), "detail": details}
    if "error_codes" not in ret["detail"]:
        ret["detail"]["error_codes"] = []

    if isinstance(errmsg, Exception):
        if not hasattr(errmsg, "anchore_error_json"):
            return ret

        # Try to load it as json
        try:
            anchore_error_json = getattr(errmsg, "anchore_error_json", None)
            if isinstance(anchore_error_json, dict):
                err_json = anchore_error_json
            else:
                err_json = json.loads(anchore_error_json)
        except (TypeError, ValueError):
            # Then it may just be a string, we cannot do anything with it
            logger.debug("Failed to parse anchore_error_json as json")
            return ret

        if {"message", "httpcode", "detail"}.issubset(set(err_json)):
            ret.update(err_json)

        try:
            if {"error_code"}.issubset(set(err_json)) and err_json.get(
                "error_code", None
            ):
                if "error_codes" not in ret["detail"]:
                    ret["detail"]["error_codes"] = []
                ret["detail"]["error_codes"].append(err_json.get("error_code"))
        except KeyError:
            logger.warn(
                "unable to marshal error details: source error {}".format(
                    errmsg.__dict__
                )
            )
    return ret


def make_anchore_exception(
    err,
    input_message=None,
    input_httpcode=None,
    input_detail=None,
    override_existing=False,
    input_error_codes=None,
):
    ret = Exception(err)

    if not input_message:
        message = str(err)
    else:
        message = input_message

    if input_detail != None:
        detail = input_detail
    else:
        detail = {"raw_exception_message": str(err)}

    if input_error_codes != None:
        error_codes = input_error_codes
    else:
        error_codes = []

    if not input_httpcode:
        httpcode = 500
    else:
        httpcode = input_httpcode

    anchore_error_json = {}
    try:
        if isinstance(err, Exception):
            if hasattr(err, "anchore_error_json"):
                anchore_error_json.update(getattr(err, "anchore_error_json"))

            if hasattr(err, "error_code"):
                error_codes.append(getattr(err, "error_code"))
    except:
        pass

    if override_existing or not anchore_error_json:
        ret.anchore_error_json = {
            "message": message,
            "detail": detail,
            "httpcode": httpcode,
        }
    else:
        ret.anchore_error_json = anchore_error_json

    if "detail" in ret.anchore_error_json:
        if "error_codes" not in ret.anchore_error_json["detail"]:
            ret.anchore_error_json["detail"]["error_codes"] = []

        if error_codes:
            ret.anchore_error_json["detail"]["error_codes"].extend(error_codes)

    return ret


def make_response_routes(apiversion, inroutes):
    return_object = {}
    httpcode = 500

    routes = []
    try:
        for route in inroutes:
            routes.append("/".join([apiversion, route]))
    except Exception as err:
        httpcode = 500
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object["httpcode"]

    else:
        httpcode = 200
        return_object = routes

    return return_object, httpcode


def update_image_record_with_analysis_data(image_record, image_data):

    image_summary_data = extract_analyzer_content(image_data, "metadata")

    try:
        image_summary_metadata = copy.deepcopy(image_summary_data)
        if image_summary_metadata:
            logger.debug("getting image summary data")

            summary_record = {}

            adm = image_summary_metadata["anchore_distro_meta"]

            summary_record["distro"] = adm.pop("DISTRO", "N/A")
            summary_record["distro_version"] = adm.pop("DISTROVERS", "N/A")

            air = image_summary_metadata["anchore_image_report"]
            airm = air.pop("meta", {})
            al = air.pop("layers", [])
            ddata = air.pop("docker_data", {})

            summary_record["layer_count"] = str(len(al))
            summary_record["dockerfile_mode"] = air.pop("dockerfile_mode", "N/A")
            summary_record["arch"] = ddata.pop("Architecture", "N/A")
            summary_record["image_size"] = str(int(airm.pop("sizebytes", 0)))

            formatted_image_summary_data = summary_record
    except Exception as err:
        formatted_image_summary_data = {}

    if formatted_image_summary_data:
        image_record.update(formatted_image_summary_data)

    dockerfile_content, dockerfile_mode = extract_dockerfile_content(image_data)
    if dockerfile_content and dockerfile_mode:
        image_record["dockerfile_mode"] = dockerfile_mode
        for image_detail in image_record["image_detail"]:
            logger.debug("setting image_detail: ")
            image_detail["dockerfile"] = str(
                base64.b64encode(dockerfile_content.encode("utf-8")), "utf-8"
            )

    return True


def extract_dockerfile_content(image_data):
    dockerfile_content = ""
    dockerfile_mode = "Guessed"

    try:
        dockerfile_content = image_data[0]["image"]["imagedata"]["image_report"][
            "dockerfile_contents"
        ]
        dockerfile_mode = image_data[0]["image"]["imagedata"]["image_report"][
            "dockerfile_mode"
        ]
    except Exception as err:
        dockerfile_content = ""
        dockerfile_mode = "Guessed"

    return dockerfile_content, dockerfile_mode


def extract_files_content(image_data):
    """
    Extract analyzed files content

    :param image_data:
    :return:
    """
    try:
        ret = {}
        fcsums = {}
        if (
            "files.sha256sums"
            in image_data["imagedata"]["analysis_report"]["file_checksums"]
        ):
            adata = image_data["imagedata"]["analysis_report"]["file_checksums"][
                "files.sha256sums"
            ]["base"]
            for k in list(adata.keys()):
                fcsums[k] = adata[k]

        if "files.allinfo" in image_data["imagedata"]["analysis_report"]["file_list"]:
            adata = image_data["imagedata"]["analysis_report"]["file_list"][
                "files.allinfo"
            ]["base"]
            for k in list(adata.keys()):
                avalue = safe_extract_json_value(adata[k])
                if k in fcsums:
                    avalue["sha256"] = fcsums[k]
                ret[k] = avalue
        return ret
    except Exception as err:
        raise Exception("could not extract/parse content info - exception: " + str(err))


def extract_os_content(image_data):
    ret = {}
    if "pkgs.allinfo" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"][
            "pkgs.allinfo"
        ]["base"]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_npm_content(image_data):
    ret = {}
    if "pkgs.npms" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"]["pkgs.npms"][
            "base"
        ]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_gem_content(image_data):
    ret = {}
    if "pkgs.gems" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"]["pkgs.gems"][
            "base"
        ]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_python_content(image_data):
    ret = {}
    if "pkgs.python" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"][
            "pkgs.python"
        ]["base"]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_java_content(image_data):
    ret = {}
    if "pkgs.java" in image_data["imagedata"]["analysis_report"]["package_list"]:
        adata = image_data["imagedata"]["analysis_report"]["package_list"]["pkgs.java"][
            "base"
        ]
        for k in list(adata.keys()):
            ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_pkg_content(image_data, content_type):
    # catchall for additional pkg types
    ret = {}
    adata = image_data["imagedata"]["analysis_report"]["package_list"][
        "pkgs.{}".format(content_type)
    ]["base"]
    for k in list(adata.keys()):
        ret[k] = safe_extract_json_value(adata[k])
    return ret


def extract_malware_content(image_data):
    # Extract malware scan
    ret = []
    clamav_content_name = "clamav"
    malware_scans = (
        image_data["imagedata"]["analysis_report"]
        .get("malware", {})
        .get("malware", {})
        .get("base", {})
    )

    for scanner_name, output in malware_scans.items():
        finding = safe_extract_json_value(output)
        ret.append(finding)

        # ret[scanner_name]
        # name = finding.get('name')
        # for result in finding.get('findings'):
        #     ret[path] = {'scanner': clamav_content_name, 'findings': path_findings }

    return ret


def extract_analyzer_content(image_data, content_type, manifest=None):
    ret = {}
    try:
        idata = image_data[0]["image"]
        imageId = idata["imageId"]

        if content_type == "files":
            return extract_files_content(idata)
        elif content_type == "os":
            return extract_os_content(idata)
        elif content_type == "npm":
            return extract_npm_content(idata)
        elif content_type == "gem":
            return extract_gem_content(idata)
        elif content_type == "python":
            return extract_python_content(idata)
        elif content_type == "java":
            return extract_java_content(idata)
        elif content_type == "malware":
            return extract_malware_content(idata)
        elif (
            "pkgs.{}".format(content_type)
            in idata["imagedata"]["analysis_report"]["package_list"]
        ):
            return extract_pkg_content(idata, content_type)
        elif content_type == "metadata":
            if (
                "image_report" in idata["imagedata"]
                and "analyzer_meta" in idata["imagedata"]["analysis_report"]
            ):
                ret = {
                    "anchore_image_report": image_data[0]["image"]["imagedata"][
                        "image_report"
                    ],
                    "anchore_distro_meta": image_data[0]["image"]["imagedata"][
                        "analysis_report"
                    ]["analyzer_meta"]["analyzer_meta"]["base"],
                }
        elif content_type == "manifest":
            ret = {}
            try:
                if manifest:
                    ret = json.loads(manifest)
            except:
                ret = {}
        elif content_type == "docker_history":
            ret = []
            try:
                ret = (
                    idata.get("imagedata", {})
                    .get("image_report", {})
                    .get("docker_history", [])
                )
            except:
                ret = []
        elif content_type == "dockerfile":
            ret = ""
            try:
                if (
                    idata.get("imagedata", {})
                    .get("image_report", {})
                    .get("dockerfile_mode", "")
                    .lower()
                    == "actual"
                ):
                    ret = (
                        idata.get("imagedata", {})
                        .get("image_report", {})
                        .get("dockerfile_contents", "")
                    )
            except:
                ret = ""

    except Exception as err:
        logger.error("could not extract/parse content info - exception: " + str(err))
        raise err

    return ret


def make_policy_record(userId, bundle, policy_source="local", active=False):
    payload = {}

    policyId = bundle["id"]

    payload["policyId"] = policyId
    payload["active"] = active
    payload["userId"] = userId
    payload["policybundle"] = bundle
    payload["policy_source"] = policy_source

    return payload


def make_eval_record(
    userId, evalId, policyId, imageDigest, tag, final_action, eval_url
):
    payload = {}

    payload["policyId"] = policyId
    payload["userId"] = userId
    payload["evalId"] = evalId
    payload["imageDigest"] = imageDigest
    payload["tag"] = tag
    payload["final_action"] = final_action
    payload["policyeval"] = eval_url
    payload["created_at"] = int(time.time())
    payload["last_updated"] = payload["created_at"]

    return payload


def safe_extract_json_value(value):
    # support the legacy serialized json string
    try:
        return json.loads(value)
    except (TypeError, json.decoder.JSONDecodeError):
        return value
