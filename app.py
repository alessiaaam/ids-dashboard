from ml.random_forest_model import predict_rf
from notifications.email_sender import send_critical_alerts
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv
from auth.login import get_user, get_user_by_id, get_all_users, users, save_users, register_user
from auth.rate_limiter import record_attempt, is_blocked
from database import log_activity, get_activity_log, get_session_summary, save_session_summary
from auth.totp import generate_totp_secret, generate_qr_code, verify_totp
from capture.pcap_reader import read_pcap
from capture.live_capture import LiveCapture
from preprocessing.packet_parser import parse_packets
from features.feature_extractor import extract_features
from alerts.alert_manager import add_alerts, get_all_alerts_list as get_all_alerts, get_count as get_alerts_count, get_by_type as get_alerts_by_type, clear_alerts
from reports.report_generator import generate_report, generate_pdf_report
from ml.gemini_explainer import explain_alerts_batch, analyze_session
import os
import threading
from datetime import datetime, timedelta

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_TIMEOUT_MINUTES"] = 8

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.before_request
def check_session_timeout():
    if current_user.is_authenticated:
        if not current_user.totp_enabled and request.endpoint not in ("setup_2fa", "logout", "static"):
            return redirect(url_for("setup_2fa"))
        last_active = session.get("last_active")
        if last_active:
            last_active = datetime.fromisoformat(last_active)
            timeout = timedelta(minutes=app.config["SESSION_TIMEOUT_MINUTES"])
            if datetime.utcnow() - last_active > timeout:
                logout_user()
                session.clear()
                return redirect(url_for("login"))
        session["last_active"] = datetime.utcnow().isoformat()

capture_instance = None
capture_lock = threading.Lock()

@app.route("/capture/start", methods=["POST"])
@login_required
def start_capture():
    global capture_instance
    with capture_lock:
        if capture_instance and capture_instance.running:
            return jsonify({"status": "already_running"})
        interface = os.getenv("CAPTURE_INTERFACE", "bridge100")
        capture_instance = LiveCapture(interface, process_live_packet)
        capture_instance.start()
    return jsonify({"status": "started"})

@app.route("/capture/stop", methods=["POST"])
@login_required
def stop_capture():
    global capture_instance
    with capture_lock:
        if capture_instance:
            capture_instance.stop()
    return jsonify({"status": "stopped"})

@app.route("/capture/status")
@login_required
def capture_status():
    global capture_instance
    running = capture_instance is not None and capture_instance.running
    return jsonify({"running": running})

live_buffer = []
live_buffer_lock = threading.Lock()

def process_live_packet(pkt):
    with live_buffer_lock:
        live_buffer.append(pkt)

def analyze_live_buffer():
    from preprocessing.packet_parser import parse_packets
    from features.feature_extractor import extract_features
    from ml.gemini_explainer import explain_alerts_batch, analyze_session
    import time

    while True:
        time.sleep(15)
        with live_buffer_lock:
            if not live_buffer:
                continue
            packets = list(live_buffer)
            live_buffer.clear()

        try:
            parsed = parse_packets(packets)
            features = extract_features(parsed, window_size=10)
            if features.empty:
                continue
            all_alerts = predict_rf(features)
            seen_types = {}
            for alert in all_alerts:
                t = alert["type"]
                if t not in seen_types:
                    seen_types[t] = alert
            final_alerts = list(seen_types.values())
            if final_alerts:
                final_alerts = explain_alerts_batch(final_alerts)
                add_alerts(final_alerts)
                summary = ""
                try:
                    summary = analyze_session(final_alerts)
                    save_session_summary(summary)
                except:
                    pass
                send_critical_alerts(final_alerts, summary)
        except Exception as e:
            print(f"Eroare analiza live: {e}")

analyzer_thread = threading.Thread(target=analyze_live_buffer, daemon=True)
analyzer_thread.start()

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

@app.route("/")
@login_required
def index():
    alerts = get_all_alerts()
    session_summary = get_session_summary()
    resp = render_template(
        "dashboard.html",
        user=current_user,
        alerts=alerts[:10],
        total_alerts=get_alerts_count(),
        alerts_by_type=get_alerts_by_type(),
        session_summary=session_summary,
    )
    from flask import make_response
    response = make_response(resp)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr
        if is_blocked(ip):
            flash("Prea multe incercari. Asteptati 15 minute.")
            return render_template("login.html")
        username = request.form.get("username")
        password = request.form.get("password")
        user = get_user(username)
        if not user or not user.check_password(password):
            record_attempt(ip)
            flash("Username sau parola incorecte.")
            return render_template("login.html")
        if user.totp_enabled:
            session["pre_2fa_user"] = username
            return redirect(url_for("verify_2fa"))
        login_user(user)
        log_activity(user.username, "LOGIN", "Autentificare reusita")
        if not user.totp_enabled:
            return redirect(url_for("setup_2fa"))
        return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    username = session.get("pre_2fa_user")
    if not username:
        return redirect(url_for("login"))
    if request.method == "POST":
        token = request.form.get("token")
        user = get_user(username)
        if verify_totp(user.totp_secret, token):
            session.pop("pre_2fa_user", None)
            login_user(user)
            return redirect(url_for("index"))
        flash("Cod 2FA incorect.")
    return render_template("verify_2fa.html")

@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = current_user
    if request.method == "POST":
        token = request.form.get("token")
        secret = session.get("totp_secret_temp")
        if verify_totp(secret, token):
            users[user.username].totp_secret = secret
            users[user.username].totp_enabled = True
            save_users()
            session.pop("totp_secret_temp", None)
            flash("2FA activat cu succes.")
            return redirect(url_for("index"))
        flash("Cod incorect. Incearca din nou.")
    secret = generate_totp_secret()
    session["totp_secret_temp"] = secret
    qr = generate_qr_code(secret, user.username)
    return render_template("setup_2fa.html", qr=qr, secret=secret)

@app.route("/logout")
@login_required
def logout():
    log_activity(current_user.username, "LOGOUT", "Deconectare")
    logout_user()
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        success, message = register_user(username, password)
        if success:
            log_activity(username, "REGISTER", "Cont nou creat")
            return redirect(url_for("login"))
        flash(message)
    return render_template("register.html")

@app.route("/admin")
@login_required
def admin_panel():
    if not current_user.is_admin():
        return redirect(url_for("index"))
    return render_template("admin.html",
        user=current_user,
        all_users=get_all_users(),
        activity_log=get_activity_log()
    )

@app.route("/admin/toggle-2fa/<username>", methods=["POST"])
@login_required
def admin_toggle_2fa(username):
    if not current_user.is_admin():
        return redirect(url_for("index"))
    target = get_user(username)
    if target:
        users[username].totp_enabled = False
        users[username].totp_secret = None
        save_users()
        log_activity(current_user.username, "ADMIN_RESET_2FA", f"2FA resetat pentru {username}")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete/<username>", methods=["POST"])
@login_required
def admin_delete_user(username):
    if not current_user.is_admin():
        return redirect(url_for("index"))
    if username == "admin":
        return redirect(url_for("admin_panel"))
    if username in users:
        del users[username]
        save_users()
        log_activity(current_user.username, "ADMIN_DELETE_USER", f"Utilizator sters: {username}")
    return redirect(url_for("admin_panel"))

@app.route("/upload-pcap", methods=["GET", "POST"])
@login_required
def upload_pcap():
    if request.method == "POST":
        file = request.files.get("pcap_file")
        if not file:
            return redirect(url_for("index"))
        import uuid
        path = f"uploads/{uuid.uuid4().hex}_{file.filename}"
        file.save(path)
        try:
            clear_alerts()
            raw = read_pcap(path)
            parsed = parse_packets(raw)
            features = extract_features(parsed)
            if not features.empty:
                all_alerts = predict_rf(features)
                seen_types = {}
                for alert in all_alerts:
                    t = alert["type"]
                    if t not in seen_types:
                        seen_types[t] = alert
                final_alerts = list(seen_types.values())
                final_alerts = explain_alerts_batch(final_alerts)
                add_alerts(final_alerts)
                summary = ""
                try:
                    summary = analyze_session(final_alerts)
                    save_session_summary(summary)
                except:
                    pass
                send_critical_alerts(final_alerts, summary)
                log_activity(current_user.username, "PCAP_UPLOAD", f"Analizat {file.filename}, {len(final_alerts)} alerte")
        except Exception as e:
            print(f"Eroare upload: {e}")
        return redirect(url_for("index"))
    return redirect(url_for("index"))

@app.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html", alerts=get_all_alerts(), user=current_user, session_summary=get_session_summary())

@app.route("/alerts/clear", methods=["POST"])
@login_required
def clear():
    clear_alerts()
    save_session_summary("")
    return redirect(url_for("alerts"))

@app.route("/report")
@login_required
def report():
    return render_template("report.html", report=generate_report(), user=current_user)

@app.route("/report/download")
@login_required
def download_report():
    from flask import send_file
    buffer = generate_pdf_report()
    return send_file(buffer, mimetype="application/pdf",
        as_attachment=True, download_name="ids_report.pdf")

@app.route("/api/status")
@login_required
def api_status():
    return jsonify({
        "status": "running",
        "user": current_user.username,
        "total_alerts": get_alerts_count(),
        "alerts_by_type": get_alerts_by_type(),
    })

if __name__ == "__main__":
    ssl_ctx = ("certs/cert.pem", "certs/key.pem") if os.path.exists("certs/cert.pem") else None
    app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=ssl_ctx)
