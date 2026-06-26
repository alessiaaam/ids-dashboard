from database import insert_alert, get_all_alerts, get_alerts_count, get_alerts_by_type, clear_all_alerts

def add_alerts(alerts):
    for alert in alerts:
        insert_alert(alert)

def get_all_alerts_list(limit=100):
    return get_all_alerts(limit)

def get_count():
    return get_alerts_count()

def get_by_type():
    return get_alerts_by_type()

def clear_alerts():
    clear_all_alerts()
