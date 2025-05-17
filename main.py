# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, abort, redirect
from db_ip      import check_user_agent, check_ip, check_ip_geo, check_allow_geo
from lic        import check_license, decrypt, ex_key, ex_login, cprint_heck_license
from scanner2   import check_ports
from stats      import click
from loguru     import logger
from db_streams import is_stream_paused
import socket

# ───────── helpers ─────────
def is_ipv6(ip: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (OSError, AttributeError):
        return False

def detect_device(ua: str) -> str:
    if not ua:               return "other"
    if "mobile" in ua.lower(): return "mobile"
    if "tablet" in ua.lower(): return "tablet"
    return "desktop"

def detect_os(ua: str) -> str:
    l = ua.lower() if ua else ""
    if   "windows" in l: return "windows"
    elif "android" in l: return "android"
    elif "iphone"  in l or "ipad" in l: return "ios"
    elif "mac os"  in l: return "macos"
    elif "linux"   in l: return "linux"
    return "other"

def detect_browser(ua: str) -> str:
    l = ua.lower() if ua else ""
    if   "chrome"  in l:                      return "chrome"
    elif "firefox" in l:                      return "firefox"
    elif "safari"  in l and "chrome" not in l:return "safari"
    elif "edge"    in l:                      return "edge"
    elif "opera"   in l or "opr" in l:        return "opera"
    return "other"

# ───────── logger / app ─────────
logger.add("api.log", rotation="500 MB", encoding="utf-8", level="DEBUG")
app = Flask(__name__)

@app.route("/", methods=["GET"])
def dev_test():
    return redirect("https://github.com/", 302)

# ───────── MAIN ─────────
@app.route("/", methods=["POST"])
def application():

    # ---------- raw json ----------
    try:
        json_in = request.get_json()
    except Exception:
        abort(403)

    logger.debug(json_in)
    logger.debug(f"[0] Pause check, incoming stream_id = {json_in.get('stream_id')}")

    # ---------- 0.a pause ----------
    stream_id = json_in.get("stream_id")
    if is_stream_paused(stream_id):
        logger.debug(f"Stream {stream_id} is PAUSED → white")
        return jsonify(status=1, redirect=1)

    # ---------- 0.b IPv6 ----------
    ip         = json_in.get("ip", "")
    if json_in.get("block_ipv6") and is_ipv6(ip):
        logger.debug(f"IPv6 {ip} blocked → white")
        return jsonify(status=1, redirect=1)

    # ---------- 0.c decode transport ----------
    try:
        encoded = decrypt(json_in.get("transport", ""))
        login   = ex_login(encoded)
    except Exception as e:
        logger.exception(e)
        encoded = ""
        login   = ""

    # ---------- 0.d Device / OS / Browser ----------
    ua_raw = json_in.get("user-agent", "")

    def early_white(reason: str, descr: str):
        logger.debug(f"[{reason}] {descr} → white")
        click({
            "ip": ip, "ua": ua_raw, "ref": json_in.get("referer",""),
            "login": login, "page": "White", "filter": reason,
            "descr": descr, "stream_id": stream_id
        })
        return jsonify(status=1, redirect=1)

    if not ua_raw:
        return early_white("UA", "empty User-Agent")

    ua_device  = detect_device(ua_raw)
    ua_os      = detect_os(ua_raw)
    ua_browser = detect_browser(ua_raw)

    # нормализуем список, чтобы сравнение было регистро-независимым
    dev_filter  = [v.lower() for v in json_in.get("device_filter",  "").split(",") if v.strip()]
    os_filter   = [v.lower() for v in json_in.get("os_filter",      "").split(",") if v.strip()]
    brw_filter  = [v.lower() for v in json_in.get("browser_filter", "").split(",") if v.strip()]

    if dev_filter and ua_device not in dev_filter:
        return early_white("Device",  f"{ua_device} not in {dev_filter}")
    if os_filter  and ua_os     not in os_filter:
        return early_white("OS",      f"{ua_os} not in {os_filter}")
    if brw_filter and ua_browser not in brw_filter:
        return early_white("Browser", f"{ua_browser} not in {brw_filter}")

    # ---------- 1. License ----------
    logger.debug(f"transport: {json_in.get('transport', '')}")
    logger.debug("[1] Check License")
    try:
        key = ex_key(encoded)
        logger.debug(cprint_heck_license(key))
        if not check_license(key):
            return jsonify(status=0, error_text="License Expired")
    except Exception as lic_e:
        logger.exception(lic_e)
        return jsonify(status=0, error_text="Request Failed (02)")

    # ---------- 2. Base stats ----------
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

    # ---------- 3. Referrer ----------
    logger.info("[2] Check Referrer")
    try:
        referer    = json_in.get("referer", "")
        custom_ref = json_in.get("cn_referer", "")
        if referer:
            logger.debug("Check Referrer enabled")
            if custom_ref and custom_ref.lower() not in referer.lower():
                stats.update({"page":"White","filter":"Referer",
                              "descr":"Referer mismatch"})
                click(stats); return jsonify(status=1, redirect=1)
            if referer == "none":
                stats.update({"page":"White","filter":"Referer",
                              "descr":"Empty Referer"})
                click(stats); return jsonify(status=1, redirect=1)
    except Exception as ref_e:
        logger.exception(ref_e); return jsonify(status=0, error_text="Request Failed (03)")

    # ---------- 4. UA blacklist ----------
    logger.info("[3] Check User-Agent blacklist")
    try:
        if check_user_agent(ua_raw):
            stats.update({"page":"White","filter":"User-Agent","descr":"UA in blacklist"})
            click(stats); return jsonify(status=1, redirect=1)
    except Exception as ua_e:
        logger.exception(ua_e); return jsonify(status=0, error_text="Request Failed (04)")

    # ---------- 5. IP blacklist ----------
    logger.info("[4] Check IP blacklist")
    try:
        if check_ip(ip):
            stats.update({"page":"White","filter":"IP","descr":"IP in blacklist"})
            click(stats); return jsonify(status=1, redirect=1)
    except Exception as ip_e:
        logger.exception(ip_e); return jsonify(status=0, error_text="Request Failed (05)")

    # ---------- 6. GEO ----------
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

    # ---------- 7. VPN / proxy ----------
    if json_in.get("check_ip") == 1:
        logger.debug("[6] Check open ports")
        try:
            if check_ports(ip):
                stats.update({"page":"White","filter":"VPN/PROXY","descr":"Anonymizer detected"})
                click(stats); return jsonify(status=1, redirect=1)
        except Exception as port_e:
            logger.exception(port_e); return jsonify(status=0, error_text="Request Failed (07)")

    # ---------- 8. OK ----------
    logger.info("All checks passed → black")
    stats.update({"page":"Black","descr":"OK"})
    click(stats)
    return jsonify(status=1, redirect=2)

# ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="127.0.0.1")
