# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, abort, redirect
from db_ip import check_user_agent, check_ip, check_ip_geo, check_allow_geo
from lic import check_license, decrypt, ex_key, ex_login, cprint_heck_license
from scanner2 import check_ports
from stats import click
from loguru import logger
from db_streams import is_stream_paused
import socket

def is_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (OSError, AttributeError):
        return False

def detect_device(ua):
    if not ua:  # если None или пустая строка
        return "Other"
    if "Mobile" in ua:
        return "Mobile"
    if "Tablet" in ua:
        return "Tablet"
    return "Desktop"

def detect_os(ua):
    if not ua:
        return "Other"
    if "Windows" in ua:
        return "Windows"
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua:
        return "iOS"
    if "iPad" in ua:
        return "iOS"
    if "Mac OS" in ua:
        return "MacOS"
    if "Linux" in ua:
        return "Linux"
    return "Other"

def detect_browser(ua):
    if not ua:
        return "Other"
    if "Chrome" in ua:
        return "Chrome"
    if "Firefox" in ua:
        return "Firefox"
    if "Safari" in ua and "Chrome" not in ua:
        return "Safari"
    if "Edge" in ua:
        return "Edge"
    if "Opera" in ua or "OPR" in ua:
        return "Opera"
    return "Other"

logger.add("api.log", rotation="500 MB", encoding="utf-8", level="DEBUG")
app = Flask(__name__)

#2
"""
@app.errorhandler(404)
def handle_notfound(e):
    abort(403)

@app.errorhandler(500)
def handle_intsrverr(e):
    abort(403)
"""

@app.route('/', methods=["GET"])
def dev_test():
    return redirect('https://github.com/', 302)


@app.route("/", methods=["POST"])
def application():
    try:
        json = request.get_json()
    except:
        abort(403)

    logger.debug(json)
    logger.debug(f"[0] Pause check, incoming stream_id = {json.get('stream_id')}")
    # 0) Pause-check -----------------------------------------------------------
    stream_id = json.get("stream_id")           # приходит из index.php
    if is_stream_paused(stream_id):
        logger.debug(f"Stream {stream_id} is PAUSED –> white")
        return jsonify(status=1, redirect=1)
    # -------------------------------------------------------------------------

    # 0.1) IPv6-block check ----------------------------------------------------
    block_ipv6 = json.get('block_ipv6', 0)
    ip = json.get('ip', '')
    if block_ipv6 == 1 and is_ipv6(ip):
        logger.debug(f"IPv6 detected ({ip}), filter enabled -> white")
        return jsonify(status=1, redirect=1)
    # -------------------------------------------------------------------------

    # 0.2) Device, OS, Browser filter ------------------------------------------
    device_filter = json.get('device_filter', '')
    os_filter = json.get('os_filter', '')
    browser_filter = json.get('browser_filter', '')
    user_agent = json.get('user-agent', '')

    allowed_devices = [d.strip() for d in device_filter.split(",") if d.strip()]
    allowed_os = [o.strip() for o in os_filter.split(",") if o.strip()]
    allowed_browsers = [b.strip() for b in browser_filter.split(",") if b.strip()]

    ua_device = detect_device(user_agent)
    ua_os = detect_os(user_agent)
    ua_browser = detect_browser(user_agent)

    if allowed_devices and ua_device not in allowed_devices:
        logger.debug(f"Device '{ua_device}' not allowed. Redirect to White Page.")
        return jsonify(status=1, redirect=1)
    if allowed_os and ua_os not in allowed_os:
        logger.debug(f"OS '{ua_os}' not allowed. Redirect to White Page.")
        return jsonify(status=1, redirect=1)
    if allowed_browsers and ua_browser not in allowed_browsers:
        logger.debug(f"Browser '{ua_browser}' not allowed. Redirect to White Page.")
        return jsonify(status=1, redirect=1)
    # -------------------------------------------------------------------------

    logger.debug(f"transport: {json['transport']}")  # Добавленная строка
    logger.debug("[1] Check License")
    try:
        encoded = decrypt(json["transport"])
        key = ex_key(encoded)
        logger.debug(f"api_key: {key}")
    except Exception as decrypt_error:
        logger.exception(decrypt_error)
        return jsonify(status=0, error_text="Request Failed (01)")
    try:
        ## !@!@
        logger.debug(cprint_heck_license(key))
        if not check_license(key):
            logger.debug("api_key not validated on the server")
            return jsonify(status=0, error_text="License Expired")
    except Exception as license_error:
        logger.exception(license_error)
        return jsonify(status=0, error_text="Request Failed (02)")

    try:
        stats = {
            "ip": json["ip"],
            "ua": json["user-agent"],
            "ref": json["referer"],
            "login": ex_login(encoded),
            "page": "",
            "filter": "",
            "descr": "",
            'stream_id': json.get('stream_id'),
        }
    except Exception as stats_e:
        logger.exception(stats_e)
    # logger.info(stats)
    logger.info("[2] Check Referrer")
    try:
        if json["referer"]:
            logger.debug("Check Referrer Enabled")
            if json["cn_referer"]:
                logger.debug(f'User set Referer: {json["cn_referer"]}')
                cn_referer = json["cn_referer"]
                if cn_referer.lower() not in json["referer"]:
                    logger.debug(
                        f"Referer does not match or custom Referer. Redirect to White Page..."
                    )
                    stats.update(
                        {
                            "page": "White",
                            "filter": "Referer",
                            "descr": "Referer не соответствует заданному",
                        }
                    )
                    click(stats)
                    return jsonify(status=1, redirect=1)
            else:
                if json["referer"] == "none":
                    logger.debug("Referer empty. Redirect to White Page...")
                    stats.update(
                        {
                            "page": "White",
                            "filter": "Referer",
                            "descr": "Пустой Referer",
                        }
                    )
                    click(stats)
                    return jsonify(status=1, redirect=1)
    except Exception as ref_error:
        logger.exception(ref_error)
        return jsonify(status=0, error_text="Request Failed (03)")

    logger.info("[3] Check User-Agent")
    try:
        if check_user_agent(str(json["user-agent"])):
            logger.debug("User Agent founded in black-list. Redirect to White Page...")
            stats.update(
                {
                    "page": "White",
                    "filter": "User-Agent",
                    "descr": "User-Agent проверка не пройдена",
                }
            )
            click(stats)
            return jsonify(status=1, redirect=1)
    except Exception as check_ua_error:
        logger.exception(check_ua_error)
        return jsonify(status=0, error_text="Request Failed (04)")

    logger.info("[4] Check IP")
    try:
        if check_ip(str(json["ip"])):
            logger.debug(
                f'IP {json["ip"]} found in black-list. Redirect to White Page...'
            )
            stats.update(
                {"page": "White", "filter": "IP", "descr": "Проверка IP не пройдена"}
            )
            click(stats)
            return jsonify(status=1, redirect=1)
    except Exception as check_ip_error:
        logger.exception(check_ip_error)
        return jsonify(status=0, error_text="Request Failed (05)")

    logger.info("[5] Check GEO in user filter")
    try:
        if json["blocked_method"] == 1:
            for country in json["country_list"].split(","):
                if country == check_ip_geo(json["ip"]):
                    logger.debug("GEO in black list. Redirect to White Page...")
                    stats.update(
                        {
                            "page": "White",
                            "filter": "GEO",
                            "descr": "Геолокация из списка запрещенных",
                        }
                    )
                    click(stats)
                    return jsonify(status=1, redirect=1)

        elif json["blocked_method"] == 2:
            if check_allow_geo(json["country_list"].split(","), json["ip"]):
                logger.debug("GEO in white list. Continue check...")
            else:
                logger.debug(
                    "GEO does not match in white list. Redirect to White Page..."
                )
                stats.update(
                    {
                        "page": "White",
                        "filter": "GEO",
                        "descr": "Геолокация не из списка разрешенных",
                    }
                )
                click(stats)
                return jsonify(status=1, redirect=1)
        else:
            logger.error("Incorrect check GEO method")
            return jsonify(status=0, error_text="Request Failed (05)")

    except Exception as check_geo_error:
        logger.exception(check_geo_error)
        return jsonify(status=0, error_text="Request Failed (06)")

    logger.info("[5] Check IP in VPN/PROXY")
    if json["check_ip"] == 1:
        logger.debug("User set enable IP Check")
        try:
            if check_ports(json["ip"]):
                logger.debug("VPN/Proxy Detected. Redirect to White Page... ")
                stats.update(
                    {
                        "page": "White",
                        "filter": "VPN/PROXY",
                        "descr": "Обнаружены средства анонимизации",
                    }
                )
                click(stats)
                return jsonify(status=1, redirect=1)
        except Exception as check_ip_error:
            logger.exception(check_ip_error)
            return jsonify(status=0, error_text="Request Failed (07)")

    logger.info("All checks passed. Redirect to Black Page...")
    stats.update({"page": "Black", "filter": "", "descr": "Проверки пройдены успешно"})
    click(stats)
    return jsonify(status=1, redirect=2)


if __name__ == "__main__":
    app.run(host="127.0.0.1")
