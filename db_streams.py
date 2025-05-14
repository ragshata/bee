import requests

FASTPANEL_URL = "https://beeclick.io"          # ← замените, если фронт на другом домене

def is_stream_paused(stream_id: int) -> bool:
    """
    True  -> поток стоит на паузе
    False -> паузы нет (или случилась ошибка)
    """
    if not stream_id:
        return False

    try:
        r = requests.get(f"{FASTPANEL_URL}/ispaused/{stream_id}", timeout=2)
        if r.ok:
            data = r.json()
            return data.get("paused") == 1
    except Exception:
        pass                       # глушим любые ошибки, считаем «паузы нет»

    return False
