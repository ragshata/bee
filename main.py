# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, abort, redirect
from db_ip       import check_user_agent, check_ip, check_ip_geo, check_allow_geo
from lic         import check_license, decrypt, ex_key, ex_login, cprint_heck_license
from scanner2    import check_ports
from stats       import click
from loguru      import logger
from db_streams  import is_stream_paused, get_stream_filters
import socket

LOW = str.lower                    # короткий алиас

# ───────── helpers ──────────────────────────────────────────
def is_ipv6(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (OSError, AttributeError):
        return False

def detect_device(ua: str) -> str:
    ua_l = ua.lower()
    if not ua_l:             return "other"
    if "mobile" in ua_l:     return "mobile"
    if "tablet" in ua_l:     return "tablet"
    return "desktop"

def detect_os(ua: str) -> str:
    ua_l = ua.lower()
    if not ua_l:             return "other"
    if "windows" in ua_l:    return "windows"
    if "android" in ua_l:    return "android"
    if "iphone"  in ua_l:    return "ios"
    if "ipad"    in ua_l:    return "ios"
    if "mac os"  in ua_l:    return "macos"
    if "linux"   in ua_l:    return "linux"
    return "other"

def detect_browser(ua: str) -> str:
    ua_l = ua.lower()
    if not ua_l:
        return "other"
    # 1) Edge (в UA бывает edg/ или edge/)
    if " edg/" in ua_l or " edge/" in ua_l:
        return "edge"
    # 2) Opera (есть ‘ opr/’ или ‘opera’)
    if " opr/" in ua_l or " opera" in ua_l:
        return "opera"
    # 3) Firefox
    if " firefox/" in ua_l:
        return "firefox"
    # 4) Chrome (проверяем после Edge/Opera, иначе они попадут сюда)
    if " chrome/" in ua_l:
        return "chrome"
    # 5) Safari – но только если это действительно Safari,
    #    т.е. нет строки ‘chrome’
    if " safari/" in ua_l and " chrome/" not in ua_l:
        return "safari"
    return "other"

# ───────── logger / app ─────────────────────────────────────
logger.add("api.log", rotation="500 MB", encoding="utf-8", level="DEBUG")
app = Flask(__name__)

@app.route("/", methods=["GET"])
def dev_test():
    return redirect("https://github.com/", 302)

# ────────── MAIN ────────────────────────────────────────────
@app.route("/", methods=["POST"])
def application():
    # ─── 0. raw JSON ────────────────────────────────────────
    try:
        json_in = request.get_json()
    except Exception:
        abort(403)

    logger.debug(json_in)
    stream_id = json_in.get("stream_id")

    # 0.a stream pause
    if is_stream_paused(stream_id):
        logger.debug(f"Stream {stream_id} paused → white")
        return jsonify(status=1, redirect=1)

    # 0.b IPv6-блок
    ip         = json_in.get("ip", "")
    block_ipv6 = json_in.get("block_ipv6", 0)
    if block_ipv6 and is_ipv6(ip):
        logger.debug(f"IPv6 {ip} blocked → white")
        return jsonify(status=1, redirect=1)

    # 0.c transport → login
    try:
        encoded = decrypt(json_in.get("transport", ""))
        login   = ex_login(encoded)
    except Exception as e:
        logger.exception(e)
        encoded = ""
        login   = ""

    # 0.d фильтры: сначала смотрим, пришли ли они прямо в запросе,
    #              иначе берем из БД
    filters_json = {
        "device_filter":  json_in.get("device_filter",  ""),
        "os_filter":      json_in.get("os_filter",      ""),
        "browser_filter": json_in.get("browser_filter", ""),
    }
    if any(filters_json.values()):
        filters = filters_json
        logger.debug("Filters taken from POST")
    else:
        filters = get_stream_filters(stream_id) or {}
        logger.debug("Filters taken from DB")

    device_filter_raw  = filters.get("device_filter",  "")
    os_filter_raw      = filters.get("os_filter",      "")
    browser_filter_raw = filters.get("browser_filter", "")

    # нормализуем списки
    dev_filter = [LOW(v.strip()) for v in device_filter_raw.split(",")  if v.strip()]
    os_filter  = [LOW(v.strip()) for v in os_filter_raw.split(",")      if v.strip()]
    brw_filter = [LOW(v.strip()) for v in browser_filter_raw.split(",") if v.strip()]

    logger.debug(f"Filters ⇒ dev:{dev_filter}, os:{os_filter}, brw:{brw_filter}")

    ua_raw = json_in.get("user-agent") or ""

    # ─── helper для быстрого выхода на white ────────────────
    def early_white(reason: str, descr: str):
        logger.debug(f"[{reason}] {descr} → white")
        click({
            "ip": ip,
            "ua": ua_raw,
            "ref": json_in.get("referer", ""),
            "login": login,
            "page": "White",
            "filter": reason,
            "descr": descr,
            "stream_id": stream_id,
        })
        return jsonify(status=1, redirect=1)

    # 0.e пустой UA
    if not ua_raw:
        return early_white("UA", "empty UA")

    ua_device  = detect_device(ua_raw)
    ua_os      = detect_os(ua_raw)
    ua_browser = detect_browser(ua_raw)

    if dev_filter and ua_device not in dev_filter:
        return early_white("Device",  f"'{ua_device}' not in {dev_filter}")
    if os_filter and ua_os not in os_filter:
        return early_white("OS",      f"'{ua_os}' not in {os_filter}")
    if brw_filter and ua_browser not in brw_filter:
        return early_white("Browser", f"'{ua_browser}' not in {brw_filter}")

    # ─── 1. license ─────────────────────────────────────────
    try:
        key = ex_key(encoded)
        if not check_license(key):
            return jsonify(status=0, error_text="License Expired")
    except Exception as lic_e:
        logger.exception(lic_e)
        return jsonify(status=0, error_text="Request Failed (02)")

    # ─── 2. базовый stats ──────────────────────────────────
    stats = {
        "ip": ip,
        "ua": ua_raw,
        "ref": json_in.get("referer", ""),
        "login": login,
        "page": "",
        "filter": "",
        "descr": "",
        "stream_id": stream_id,
    }

    # ─── 3. Referrer ───────────────────────────────────────
    logger.info("[2] Check Referrer")
    try:
        referer    = json_in.get("referer", "")
        custom_ref = json_in.get("cn_referer", "")
        if referer:
            logger.debug("Check Referrer enabled")
            if custom_ref and LOW(custom_ref) not in LOW(referer):
                stats.update({"page":"White","filter":"Referer","descr":"Referer mismatch"})
                click(stats); return jsonify(status=1, redirect=1)
            if referer == "none":
                stats.update({"page":"White","filter":"Referer","descr":"Empty Referer"})
                click(stats); return jsonify(status=1, redirect=1)
    except Exception as ref_e:
        logger.exception(ref_e); return jsonify(status=0, error_text="Request Failed (03)")

    # ─── 4. UA blacklist ───────────────────────────────────
    logger.info("[3] Check User-Agent blacklist")
    try:
        if check_user_agent(ua_raw):
            stats.update({"page":"White","filter":"User-Agent","descr":"UA in blacklist"})
            click(stats); return jsonify(status=1, redirect=1)
    except Exception as ua_e:
        logger.exception(ua_e); return jsonify(status=0, error_text="Request Failed (04)")

    # ─── 5. IP blacklist ───────────────────────────────────
    logger.info("[4] Check IP blacklist")
    try:
        if check_ip(ip):
            stats.update({"page":"White","filter":"IP","descr":"IP in blacklist"})
            click(stats); return jsonify(status=1, redirect=1)
    except Exception as ip_e:
        logger.exception(ip_e); return jsonify(status=0, error_text="Request Failed (05)")

    # ─── 6. GEO ────────────────────────────────────────────
    logger.info("[5] Check GEO filter")
    try:
        blocked_method = json_in.get("blocked_method")
        country_list   = [c.strip().upper() for c in json_in.get("country_list","").split(",") if c.strip()]
        user_country   = check_ip_geo(ip)

        if blocked_method == 1 and user_country in country_list:
            stats.update({"page":"White","filter":"GEO","descr":"Country in blacklist"})
            click(stats); return jsonify(status=1, redirect=1)

        if blocked_method == 2 and user_country not in country_list:
            stats.update({"page":"White","filter":"GEO","descr":"Country not in whitelist"})
            click(stats); return jsonify(status=1, redirect=1)
    except Exception as geo_e:
        logger.exception(geo_e); return jsonify(status=0, error_text="Request Failed (06)")

    # ─── 7. VPN / proxy ────────────────────────────────────
    if json_in.get("check_ip") == 1:
        logger.debug("[6] Check open ports")
        try:
            if check_ports(ip):
                stats.update({"page":"White","filter":"VPN/PROXY","descr":"Anonymizer detected"})
                click(stats); return jsonify(status=1, redirect=1)
        except Exception as port_e:
            logger.exception(port_e); return jsonify(status=0, error_text="Request Failed (07)")

    # ─── 8. success ────────────────────────────────────────
    logger.info("All checks passed → black")
    stats.update({"page":"Black","descr":"OK"})
    click(stats)
    return jsonify(status=1, redirect=2)

# ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="127.0.0.1")
