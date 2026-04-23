#!/usr/bin/env python3
import argparse
import atexit
import importlib.util
import ipaddress
import json
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from functools import wraps
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from flask import Flask, abort, jsonify, redirect, render_template_string, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


GATEWAY_HOST = "0.0.0.0"
GATEWAY_PORT = 8000

TARGET_APPS: List[Tuple[str, str, int]] = [
    ("Облік обладнання", "Eq_man/app.py", 5001),
    ("GLPI/ESET", "GLPI/app1.py", 5002),
    ("Ключі", "Keys/app2.py", 5003),
    ("Контроль присвоєння рангу та спеціального звання", "kadri/app3.py", 5004),
]

EXTERNAL_LINKS: List[Tuple[str, str, str]] = [
    ("ASKOD", "https://askod.int.dasu/askod/Loginv4.aspx", "icons/fortinet.svg"),
    ("ESET", "https://192.168.52.12/era/webconsole/", "icons/era-e.svg"),
    ("Prozorro", "https://sas.prozorro.gov.ua/login", "icons/prozorro.svg"),
    ("Fortinet", "https://192.168.106.1/login?redir=%2F", "icons/fortinet.svg"),
    ("Zabbix", "http://192.168.106.2/zabbix/", "icons/zabbix.svg"),
    ("GLPI", "http://192.168.52.105/", "icons/glpi.svg"),
]

PING_TARGETS: List[Tuple[str, str]] = [
    ("Google", "8.8.8.8"),
    ("АСКОД", "10.10.27.21"),
    ("Fortigate", "192.168.106.1"),
    ("IT", "192.168.106.101"),
    ("Закупівлі", "192.168.106.102"),
    ("Кадри", "192.168.106.103"),
]

USER_ICON_KEY_MAP: Dict[str, str] = {
    "ASKOD": "askod",
    "ESET": "era",
    "Prozorro": "prozorro",
    "Fortinet": "fortinet",
    "Zabbix": "zabbix",
    "GLPI": "glpi",
}
USER_ICON_DIR = Path(__file__).resolve().parent / "static" / "user-icons"
USER_ICON_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".svg")
DATA_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "gateway.db"
DEFAULT_PASSWORD = "D@$UofZT"
CAROUSEL_DIR = Path(os.environ.get("GATEWAY_CAROUSEL_DIR", str(Path.home() / "GatewayCarouselPhotos"))).expanduser().resolve()
LOGO_DIR = Path(__file__).resolve().parent / "logo"
LOGO_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".svg")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("GATEWAY_SECRET_KEY", "change-this-secret")
app.config["SESSION_COOKIE_NAME"] = os.environ.get("GATEWAY_SESSION_COOKIE_NAME", "gateway_session")
child_processes: Dict[str, subprocess.Popen] = {}
_shutdown_started = False

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Gateway</title>
  <link rel="icon" href="/logo1/logo.ico" type="image/x-icon">
  <style>
    * { box-sizing:border-box; }
    body { margin:0; font-family: Inter, sans-serif; background:#0b1220; color:#e5e7eb; min-height:100vh; }
    .auth-layout { width:100vw; min-height:100vh; display:grid; grid-template-columns:1fr 1fr; background:#0f172a; overflow:hidden; }
    .auth-left { background:#fff; color:#0f172a; border-top-right-radius:56px; border-bottom-right-radius:56px; display:flex; align-items:center; justify-content:center; padding:24px; }
    .auth-logo { max-width:70%; max-height:70%; object-fit:contain; }
    .auth-logo-placeholder { text-align:center; color:#64748b; font-size:.95rem; line-height:1.5; max-width:320px; }
    .auth-right { display:flex; align-items:center; justify-content:center; padding:24px; }
    .card { width:min(420px,100%); background:#111827; border:1px solid #334155; border-radius:14px; padding:20px; }
    h1 { margin:0 0 12px; text-align:center; font-size:1.2rem; }
    label { display:block; font-size:.86rem; color:#94a3b8; margin-bottom:4px; }
    input { width:100%; box-sizing:border-box; margin-bottom:10px; border:1px solid #334155; border-radius:8px; background:#020617; color:#fff; padding:9px 10px; }
    button { width:100%; border:1px solid #4f46e5; border-radius:8px; background:linear-gradient(180deg,#6366f1,#4f46e5); color:#fff; padding:10px; font-weight:700; cursor:pointer; }
    .secondary { margin-top:8px; border-color:#475569; background:linear-gradient(180deg,#334155,#1e293b); }
    .hint { font-size:.82rem; color:#94a3b8; text-align:center; margin-top:8px; }
    .err { color:#fecaca; background:#450a0a; border:1px solid #7f1d1d; border-radius:8px; padding:8px; margin-bottom:10px; display:none; }
    .ok { color:#bbf7d0; background:#052e16; border:1px solid #166534; border-radius:8px; padding:8px; margin-bottom:10px; display:none; }
    .hidden { display:none; }
	    @media (max-width: 900px) {
	      .auth-layout { grid-template-columns:1fr; min-height:100vh; }
	      .auth-left { min-height:220px; border-top-right-radius:0; border-bottom-left-radius:56px; border-bottom-right-radius:56px; }
	    }
  </style>
</head>
<body>
  <div class="auth-layout">
    <div class="auth-left">
      {% if logo_url %}
      <img class="auth-logo" src="{{ logo_url }}" alt="Логотип" />
      {% else %}
      <div class="auth-logo-placeholder">
        Додайте зображення у папку <strong>logo</strong> у корені проєкту.<br/>
        Підтримуються: png, jpg, jpeg, webp, svg.
      </div>
      {% endif %}
    </div>
    <div class="auth-right">
      <div class="card">
        <h1 id="authTitle">Вхід</h1>
        <div id="loginErr" class="err"></div>
        <div id="registerOk" class="ok"></div>

        <div id="loginView">
          <label for="username">Користувач</label>
          <input id="username" type="text" autocomplete="username" />
          <label for="password">Пароль</label>
          <input id="password" type="password" autocomplete="current-password" />
          <button id="loginBtn" type="button">Увійти</button>
          <button id="showRegisterBtn" type="button" class="secondary">Реєстрація</button>
        </div>

        <div id="registerView" class="hidden">
          <label for="registerUsername">Ім'я користувача</label>
          <input id="registerUsername" type="text" autocomplete="username" />
          <label for="registerPassword">Пароль</label>
          <input id="registerPassword" type="password" autocomplete="new-password" />
          <button id="registerBtn" type="button">Зареєструватися</button>
          <button id="showLoginBtn" type="button" class="secondary">Повернутись до входу</button>
          <div class="hint">Після подачі заявки очікуйте підтвердження адміна.</div>
        </div>
      </div>
    </div>
  </div>
  <script>
    const err = document.getElementById("loginErr");
    const registerOk = document.getElementById("registerOk");
    const authTitle = document.getElementById("authTitle");
    const loginView = document.getElementById("loginView");
    const registerView = document.getElementById("registerView");
    function toggleAuthMode(isRegister) {
      err.style.display = "none";
      registerOk.style.display = "none";
      loginView.classList.toggle("hidden", isRegister);
      registerView.classList.toggle("hidden", !isRegister);
      authTitle.textContent = isRegister ? "Реєстрація" : "Вхід";
    }
    document.getElementById("loginBtn").addEventListener("click", async () => {
      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value;
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        err.textContent = "Невірний логін або пароль.";
        err.style.display = "block";
        return;
      }
      window.location.href = "/";
    });
    document.getElementById("showRegisterBtn").addEventListener("click", () => toggleAuthMode(true));
    document.getElementById("showLoginBtn").addEventListener("click", () => toggleAuthMode(false));
    document.getElementById("registerBtn").addEventListener("click", async () => {
      const username = document.getElementById("registerUsername").value.trim();
      const password = document.getElementById("registerPassword").value;
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (!res.ok) {
        err.textContent = "Текст по дебільному написаний";
        err.style.display = "block";
        return;
      }
      document.getElementById("registerUsername").value = "";
      document.getElementById("registerPassword").value = "";
      registerOk.textContent = "Очікуйте підтвердження адміна";
      registerOk.style.display = "block";
    });
  </script>
</body>
</html>
"""


PAGE_TEMPLATE = """
<!doctype html>
<html lang="uk">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Gateway</title>
  <style>
    :root {
      --bg: #0b1220;
      --bg-secondary: #111827;
      --card: #161f33;
      --card-border: #28344f;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --accent: #6366f1;
      --accent-dark: #4f46e5;
      --ok: #34d399;
      --icon-hover: #1f2a44;
      --danger: #ef4444;
      --panel: #0f172a;
      --panel-border: #334155;
      --chart: #60a5fa;
      --map-bg: #020617;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at top, #1e293b 0%, var(--bg) 45%, #060b16 100%);
      color: var(--text);
      min-height: 100vh;
      padding: 16px;
    }

    .layout {
      width: min(1500px, 100%);
      margin: 0 auto;
      display: grid;
      gap: 14px;
      grid-template-columns: minmax(260px, 0.9fr) minmax(620px, 1.7fr) minmax(370px, 1.2fr);
      align-items: start;
    }

    .top-bar {
      width: min(1500px, 100%);
      margin: 0 auto 14px;
      background: linear-gradient(180deg, #17233b 0%, #111a2e 100%);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      box-shadow: 0 16px 36px rgba(0, 0, 0, 0.35);
      padding: 10px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }

    .top-bar-left,
    .top-bar-right {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .top-user-name {
      color: #e2e8f0;
      font-weight: 700;
      font-size: 0.94rem;
      white-space: nowrap;
    }

    .top-logout-btn {
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: rgba(99, 102, 241, 0.16);
      color: #fff;
      border-radius: 8px;
      padding: 7px 12px;
      cursor: pointer;
      font-size: 0.86rem;
      font-weight: 600;
    }

    .top-logout-btn:hover {
      filter: brightness(1.12);
    }

    .left-column {
      display: grid;
      gap: 14px;
    }

    .panel {
      background: linear-gradient(180deg, #18243d 0%, var(--card) 100%);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      box-shadow: 0 16px 36px rgba(0, 0, 0, 0.42);
      padding: 16px;
    }

    .panel-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 10px;
    }

    .section-title {
      margin-top: 28px;
      margin-bottom: 10px;
      font-weight: 700;
      font-size: 1rem;
      color: #cbd5e1;
      text-align: center;
    }

    .panel-header .section-title {
      margin: 0;
      text-align: left;
    }

    .add-btn {
      width: 30px;
      height: 30px;
      border-radius: 999px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: linear-gradient(180deg, var(--accent), var(--accent-dark));
      color: #fff;
      font-size: 1.2rem;
      font-weight: 700;
      cursor: pointer;
      line-height: 1;
      display: grid;
      place-items: center;
      padding: 0;
    }

    .add-btn:hover { filter: brightness(1.1); }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(2, 6, 23, 0.68);
      backdrop-filter: blur(3px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      padding: 14px;
    }

    .modal-backdrop.open {
      display: flex;
    }

    .modal {
      width: min(520px, 100%);
      background: #0b1220;
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      padding: 16px;
    }

    .modal h3 {
      margin: 0 0 10px;
      font-size: 1.1rem;
    }

    .field {
      margin-bottom: 10px;
    }

    .field label {
      display: block;
      font-size: 0.85rem;
      margin-bottom: 4px;
      color: var(--muted);
    }

    .field input {
      width: 100%;
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      background: #020617;
      color: #fff;
      padding: 8px 10px;
    }

    .modal-actions {
      display: flex;
      gap: 8px;
      justify-content: flex-end;
      margin-top: 12px;
      flex-wrap: wrap;
    }

    .modal-btn {
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      background: #1e293b;
      color: #fff;
      padding: 8px 12px;
      cursor: pointer;
    }

    .modal-btn.primary {
      background: linear-gradient(180deg, var(--accent), var(--accent-dark));
    }

    .custom-list {
      margin-top: 12px;
      border-top: 1px solid var(--panel-border);
      padding-top: 10px;
      display: grid;
      gap: 8px;
      max-height: 180px;
      overflow: auto;
    }

    .custom-item {
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      padding: 8px;
      background: #020617;
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 8px;
      align-items: center;
    }

    .custom-item-meta {
      font-size: 0.83rem;
      color: var(--muted);
    }

    .custom-item-actions {
      display: flex;
      gap: 6px;
    }

    .custom-item-actions button {
      border: 1px solid var(--panel-border);
      background: #1e293b;
      color: #fff;
      border-radius: 6px;
      padding: 4px 8px;
      cursor: pointer;
      font-size: 0.8rem;
    }

    .custom-item-actions .delete {
      border-color: #7f1d1d;
      background: #450a0a;
    }

    .map-frame {
      width: 100%;
      min-height: 420px;
      border: 1px solid var(--panel-border);
      border-radius: 12px;
      overflow: hidden;
      background: var(--map-bg);
    }

    .map-frame iframe {
      width: 100%;
      min-height: 420px;
      border: 0;
    }

    .map-shell {
      position: relative;
      width: 100%;
      min-height: 420px;
    }

    .carousel-stage {
      position: absolute;
      inset: 0;
      display: none;
      background: #020617;
    }

    .carousel-stage.active {
      display: block;
    }

    .carousel-image {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      object-fit: cover;
      opacity: 0;
      transform: scale(1.03);
      transition: opacity .9s ease, transform 1.2s ease;
    }

    .carousel-image.visible {
      opacity: 1;
      transform: scale(1);
    }

    .secret-toggle {
      border: 0;
      background: transparent;
      color: rgba(255, 255, 255, 0.05);
      cursor: pointer;
      padding: 0 2px;
      font-size: 0.7rem;
      vertical-align: middle;
    }

    .secret-toggle:hover {
      color: rgba(255, 255, 255, 0.18);
    }

    .alert-reason {
      margin-top: 8px;
      font-size: 0.86rem;
      color: #fecaca;
      background: rgba(69, 10, 10, 0.7);
      border: 1px solid #7f1d1d;
      border-radius: 8px;
      padding: 8px 10px;
      display: none;
    }

    .card {
      width: 100%;
      background: linear-gradient(180deg, #18243d 0%, var(--card) 100%);
      border: 1px solid var(--card-border);
      border-radius: 20px;
      box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
      padding: 28px;
    }

    .settings-btn {
      width: 30px;
      height: 30px;
      border-radius: 999px;
      border: 1px solid rgba(255, 255, 255, 0.2);
      background: #1e293b;
      color: #fff;
      cursor: pointer;
      display: grid;
      place-items: center;
      font-size: 1rem;
      line-height: 1;
      padding: 0;
    }

    .settings-btn:hover {
      filter: brightness(1.1);
    }

    .password-change-btn {
      width: auto;
      padding: 0 10px;
      font-size: 0.76rem;
      font-weight: 700;
      white-space: nowrap;
    }

    .notifications-btn {
      width: auto;
      padding: 0 10px;
      font-size: 0.76rem;
      font-weight: 700;
      white-space: nowrap;
    }

    .header-actions {
      display: flex;
      gap: 8px;
    }

    #soundModalBackdrop.password-only .sound-only {
      display: none !important;
    }

    #soundModalBackdrop.notifications-only .hide-on-notifications {
      display: none !important;
    }

    #soundModalBackdrop.users-only .hide-on-users {
      display: none !important;
    }

    #soundModalBackdrop.carousel-only .hide-on-carousel {
      display: none !important;
    }

    .notice-toast {
      position: fixed;
      right: 18px;
      bottom: 18px;
      z-index: 1200;
      min-width: 260px;
      max-width: min(360px, calc(100vw - 36px));
      border-radius: 10px;
      border: 1px solid #7f1d1d;
      background: #450a0a;
      color: #fecaca;
      padding: 10px 12px;
      box-shadow: 0 12px 28px rgba(0, 0, 0, 0.4);
      display: none;
      font-size: 0.88rem;
    }

    .notice-toast.show {
      display: block;
    }

    .clock {
      text-align: center;
      font-size: clamp(1.45rem, 2.4vw, 1.95rem);
      font-weight: 900;
      color: #f8fafc;
      margin-bottom: 8px;
      letter-spacing: .01em;
      line-height: 1.3;
      white-space: nowrap;
    }

    h1 {
      margin: 6px 0 8px;
      font-size: 1.7rem;
      color: #f8fafc;
      text-align: center;
    }

    .grid {
      margin-top: 24px;
      display: grid;
      gap: 12px;
    }

    .service-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .external-grid {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }

    .btn {
      display: block;
      text-decoration: none;
      background: linear-gradient(180deg, var(--accent), var(--accent-dark));
      color: #fff;
      border-radius: 12px;
      padding: 14px 16px;
      font-weight: 600;
      text-align: center;
      transition: transform .12s ease, filter .2s ease;
      border: 1px solid rgba(255, 255, 255, 0.08);
    }

    .btn:hover {
      transform: translateY(-2px);
      filter: brightness(1.1);
    }

    .icon-card {
      background: var(--bg-secondary);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 14px;
      text-align: center;
    }

    .icon-btn {
      display: grid;
      place-items: center;
      text-decoration: none;
      color: var(--text);
      border-radius: 12px;
      padding: 10px;
      transition: transform .12s ease, background .2s ease;
    }

    .icon-btn:hover {
      transform: translateY(-2px);
      background: var(--icon-hover);
    }

    .service-icon {
      width: 64px;
      height: 64px;
      object-fit: contain;
      display: block;
      margin-bottom: 8px;
      filter: drop-shadow(0 4px 10px rgba(0, 0, 0, 0.4));
    }

    .service-name {
      font-weight: 700;
      font-size: 0.95rem;
      color: #e2e8f0;
    }

    .ping-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(160px, 1fr));
      gap: 10px;
    }

    .ping-card {
      border: 1px solid var(--panel-border);
      background: var(--panel);
      border-radius: 10px;
      padding: 8px;
    }

    .ping-title {
      font-weight: 700;
      margin-bottom: 4px;
      font-size: 0.9rem;
    }

    .ping-meta {
      font-size: 0.78rem;
      color: var(--muted);
      margin-bottom: 4px;
    }

    .ping-meta .down {
      color: var(--danger);
      font-weight: 700;
    }


    .carousel-thumb-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(72px, 1fr));
      gap: 8px;
      margin-top: 8px;
    }

    .carousel-thumb-item {
      position: relative;
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      overflow: hidden;
      background: #020617;
      height: 72px;
    }

    .carousel-thumb-item img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
    }

    .carousel-thumb-delete {
      position: absolute;
      top: 3px;
      right: 3px;
      width: 18px;
      height: 18px;
      border-radius: 999px;
      border: 1px solid #7f1d1d;
      background: rgba(69, 10, 10, 0.9);
      color: #fff;
      font-size: 0.75rem;
      cursor: pointer;
      line-height: 1;
      padding: 0;
    }

    canvas {
      width: 100%;
      height: 72px;
      display: block;
      border-radius: 8px;
      background: #020617;
      border: 1px solid #1e293b;
    }

    .calendar-panel {
      padding: 16px;
      background: linear-gradient(180deg, #17253f 0%, #10192d 100%);
    }

    .calendar-nav {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 10px;
    }

    .calendar-month-title {
      font-weight: 700;
      color: #f1f5f9;
      text-align: center;
      flex: 1;
      font-size: 1rem;
      letter-spacing: 0.01em;
    }

    .calendar-nav-btn {
      border: 1px solid var(--panel-border);
      background: rgba(99, 102, 241, 0.16);
      color: #fff;
      border-radius: 8px;
      width: 30px;
      height: 30px;
      cursor: pointer;
      line-height: 1;
      font-size: 1rem;
      transition: transform 0.12s ease, filter 0.15s ease;
    }

    .calendar-nav-btn:hover {
      transform: translateY(-1px);
      filter: brightness(1.2);
    }

    .calendar-weekdays,
    .calendar-grid {
      display: grid;
      grid-template-columns: repeat(7, minmax(0, 1fr));
      gap: 6px;
    }

    .calendar-weekdays {
      margin-bottom: 6px;
    }

    .calendar-weekday {
      text-align: center;
      font-size: 0.75rem;
      color: var(--muted);
      padding: 2px 0;
    }

    .calendar-day {
      min-height: 46px;
      border: 1px solid var(--panel-border);
      border-radius: 8px;
      background: linear-gradient(180deg, #0c162a 0%, #020617 100%);
      color: #fff;
      cursor: pointer;
      font-size: 0.85rem;
      padding: 6px;
      text-align: left;
      position: relative;
      transition: transform 0.12s ease, border-color 0.15s ease, background 0.15s ease;
    }

    .calendar-day:hover {
      transform: translateY(-1px);
      border-color: #475569;
      background: linear-gradient(180deg, #1b2a45 0%, #0b1326 100%);
    }

    .calendar-day.muted {
      opacity: 0.45;
      cursor: default;
    }

    .calendar-day.has-control {
      border-color: #14b8a6;
      box-shadow: inset 0 0 0 1px rgba(45, 212, 191, 0.65), 0 0 0 1px rgba(20, 184, 166, 0.2);
      background: linear-gradient(180deg, rgba(20, 184, 166, 0.3), rgba(15, 23, 42, 0.95));
    }

    .calendar-day.today {
      border-color: #60a5fa;
      box-shadow: inset 0 0 0 1px rgba(96, 165, 250, 0.6);
    }

    .calendar-day-label {
      display: block;
      font-weight: 700;
      margin-bottom: 3px;
    }

    .calendar-day-note {
      display: block;
      font-size: 0.7rem;
      color: #cbd5e1;
      line-height: 1.2;
      max-height: 30px;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .calendar-next-control {
      margin-top: 10px;
      border: 1px solid var(--panel-border);
      border-radius: 10px;
      background: rgba(15, 23, 42, 0.75);
      color: #cbd5e1;
      font-size: 0.83rem;
      padding: 8px 10px;
      min-height: 42px;
      line-height: 1.35;
    }

    .calendar-next-control strong {
      color: #f8fafc;
    }

    @media (max-width: 1220px) {
      .top-bar {
        flex-wrap: wrap;
      }

      .layout {
        grid-template-columns: 1fr;
      }

      .map-frame,
      .map-frame iframe {
        min-height: 360px;
      }

      .service-grid,
      .external-grid {
        grid-template-columns: 1fr;
      }

      .clock {
        white-space: normal;
      }
    }
  </style>
</head>
<body>
  <div class="top-bar">
    <div class="top-bar-left">
      <button id="openPasswordChange" class="settings-btn password-change-btn" type="button">Зміна паролю</button>
      <button id="openNotifications" class="settings-btn notifications-btn" type="button">Сповіщення</button>
      <button id="openUsersManagement" class="settings-btn notifications-btn" type="button" style="display:none;">Користувачі</button>
      <button id="openCarouselSettings" class="settings-btn notifications-btn" type="button" style="display:none;">Карусель</button>
    </div>
    <div class="top-bar-right">
      <span id="topUserName" class="top-user-name">-</span>
      <button id="topLogoutBtn" class="top-logout-btn" type="button">Вихід</button>
    </div>
  </div>
  <div class="layout">
    <div class="left-column">
      <aside class="panel">
        <div class="section-title" style="margin-top:0;">
          Мапа тривог{% if is_bohdan %}<button id="secretCarouselToggle" class="secret-toggle" type="button" aria-label="Перемкнути режим">•</button>{% endif %}
        </div>
        <div class="map-frame">
          <div class="map-shell">
            <iframe id="alertsFrame" src="https://alerts.in.ua" title="Мапа тривог alerts.in.ua" loading="lazy"></iframe>
            <div id="carouselStage" class="carousel-stage"></div>
          </div>
        </div>
        <div id="zhytomyrAlertReason" class="alert-reason"></div>
      </aside>
      <aside class="panel calendar-panel">
        <div class="panel-header">
          <div class="section-title">Календар контролів</div>
        </div>
        <div class="calendar-nav">
          <button id="calendarPrevMonth" type="button" class="calendar-nav-btn" aria-label="Попередній місяць">‹</button>
          <div id="calendarMonthLabel" class="calendar-month-title">-</div>
          <button id="calendarNextMonth" type="button" class="calendar-nav-btn" aria-label="Наступний місяць">›</button>
        </div>
        <div class="calendar-weekdays" id="calendarWeekdays"></div>
        <div class="calendar-grid" id="calendarGrid"></div>
        <div id="calendarNextControl" class="calendar-next-control">Дата наступного контролю: —</div>
      </aside>

    </div>

    <main class="card">
      <div id="clock" class="clock">--:--:-- -- ---- ----</div>
      <h1>Оберіть сервіс для переходу</h1>

      <section class="grid service-grid">
        {% for item in items %}
          <div>
            <a class="btn" href="{{ item.url }}" target="_blank" rel="noopener">{{ item.name }}</a>
          </div>
        {% endfor %}
      </section>

      <div class="section-title">Зовнішні сервіси</div>
      <section class="grid external-grid">
        {% for item in external_items %}
          <div class="icon-card">
            <a class="icon-btn" href="{{ item.url }}" target="_blank" rel="noopener">
              <img class="service-icon" src="{{ item.icon }}" alt="{{ item.name }}" />
              <div class="service-name">{{ item.name }}</div>
            </a>
          </div>
        {% endfor %}
      </section>

    </main>

    <aside class="panel">
      <div class="panel-header">
        <div class="section-title">Ping у реальному часі</div>
        <div class="header-actions">
          <button id="openPingModal" class="add-btn" type="button" aria-label="Додати ping">+</button>
        </div>
      </div>
      <div class="ping-grid" id="pingGrid"></div>
    </aside>
  </div>

  <div class="modal-backdrop" id="pingModalBackdrop" role="dialog" aria-modal="true" aria-labelledby="pingModalTitle">
    <div class="modal">
      <h3 id="pingModalTitle">Користувацькі ping-цілі</h3>
      <div class="field">
        <label for="targetName">Назва</label>
        <input id="targetName" type="text" maxlength="60" placeholder="Напр. Сервер файлів" />
      </div>
      <div class="field">
        <label for="targetHost">IP-адреса</label>
        <input id="targetHost" type="text" maxlength="64" placeholder="Напр. 192.168.1.10" />
      </div>
      <div class="modal-actions">
        <button id="cancelEdit" type="button" class="modal-btn">Скасувати редагування</button>
        <button id="saveTarget" type="button" class="modal-btn primary">Зберегти</button>
        <button id="closePingModal" type="button" class="modal-btn">Закрити</button>
      </div>
      <div class="custom-list" id="customTargetList"></div>
    </div>
  </div>

  <div class="modal-backdrop" id="soundModalBackdrop" role="dialog" aria-modal="true" aria-labelledby="soundModalTitle">
    <div class="modal">
      <h3 id="soundModalTitle">Налаштування</h3>
      <div class="field hide-on-notifications hide-on-users hide-on-carousel">
        <label><strong>Обліковий запис: <span id="currentUserLabel">-</span></strong></label>
      </div>
      <div class="field hide-on-notifications hide-on-users hide-on-carousel">
        <label for="oldPassword">Поточний пароль</label>
        <input id="oldPassword" type="password" />
      </div>
      <div class="field hide-on-notifications hide-on-users hide-on-carousel">
        <label for="newPassword">Новий пароль</label>
        <input id="newPassword" type="password" />
      </div>
      <div class="field sound-only hide-on-users hide-on-carousel">
        <label><input id="soundEnabled" type="checkbox" checked /> Увімкнути звук</label>
      </div>
      <div class="field sound-only hide-on-users hide-on-carousel">
        <label for="customSoundFile">Власний звук (mp3/wav/ogg)</label>
        <input id="customSoundFile" type="file" accept="audio/*" />
      </div>
      <div class="modal-actions">
        <button id="changePasswordBtn" type="button" class="modal-btn hide-on-notifications hide-on-users hide-on-carousel">Змінити пароль</button>
        <button id="logoutBtn" type="button" class="modal-btn sound-only hide-on-notifications hide-on-users hide-on-carousel">Вийти</button>
        <button id="testSoundBtn" type="button" class="modal-btn sound-only hide-on-users hide-on-carousel">Тест звуку</button>
        <button id="resetSoundBtn" type="button" class="modal-btn sound-only hide-on-notifications hide-on-users hide-on-carousel">Скинути</button>
        <button id="saveSoundBtn" type="button" class="modal-btn primary sound-only hide-on-users hide-on-carousel">Зберегти</button>
        <button id="closeSoundModal" type="button" class="modal-btn">Закрити</button>
      </div>
      <div id="bohdanCarouselSection" class="sound-only hide-on-notifications hide-on-users" style="display:none; margin-top:12px; border-top:1px solid var(--panel-border); padding-top:10px;">
        <h4 style="margin:0 0 8px;">Карусель фото для мапи тривог</h4>
        <div class="field">
          <label for="carouselUploadInput">Додати фото (одне або декілька)</label>
          <input id="carouselUploadInput" type="file" accept="image/*" multiple />
        </div>
        <div class="modal-actions" style="justify-content:flex-start;">
          <button id="uploadCarouselImagesBtn" type="button" class="modal-btn primary">Завантажити фото</button>
        </div>
        <div id="carouselThumbs" class="carousel-thumb-grid"></div>
      </div>
            <div id="adminUsersSection" class="sound-only hide-on-notifications hide-on-carousel" style="display:none; margin-top:12px; border-top:1px solid var(--panel-border); padding-top:10px;">
        <h4 style="margin:0 0 8px;">Користувачі</h4>
        <div class="field">
          <label>Заявки на реєстрацію</label>
          <div id="pendingUsersList" class="custom-list"></div>
        </div>
        <div class="field">
          <label>Активні користувачі</label>
          <div id="adminUsersList" class="custom-list"></div>
        </div>
      </div>
    </div>
  </div>


  <div id="pingAlertToast" class="notice-toast" role="status" aria-live="polite"></div>

  <div class="modal-backdrop" id="calendarModalBackdrop" role="dialog" aria-modal="true" aria-labelledby="calendarModalTitle">
    <div class="modal">
      <h3 id="calendarModalTitle">Контроль на дату</h3>
      <div class="field">
        <label for="calendarControlDate">Дата</label>
        <input id="calendarControlDate" type="text" readonly />
      </div>
      <div class="field">
        <label for="calendarControlName">Назва контролю</label>
        <input id="calendarControlName" type="text" maxlength="120" placeholder="Введіть назву контролю" />
      </div>
      <div class="modal-actions">
        <button id="calendarDeleteBtn" type="button" class="modal-btn">Видалити</button>
        <button id="calendarSaveBtn" type="button" class="modal-btn primary">Зберегти</button>
        <button id="calendarCloseBtn" type="button" class="modal-btn">Закрити</button>
      </div>
    </div>
  </div>

  <script>
    const months = ["січня", "лютого", "березня", "квітня", "травня", "червня", "липня", "серпня", "вересня", "жовтня", "листопада", "грудня"];
    function formatClock() {
      const now = new Date();
      const hh = String(now.getHours()).padStart(2, "0");
      const mm = String(now.getMinutes()).padStart(2, "0");
      const ss = String(now.getSeconds()).padStart(2, "0");
      const day = now.getDate();
      const month = months[now.getMonth()];
      const year = now.getFullYear();
      return `${hh}:${mm}:${ss} ${day} ${month}, ${year}`;
    }

    const clockEl = document.getElementById("clock");
    function tick() {
      clockEl.textContent = formatClock();
    }
    tick();
    setInterval(tick, 1000);

    const storageKey = "gateway_custom_ping_targets_v1";
    const defaultPingTargets = {{ ping_targets|tojson }};
    let customTargets = loadCustomTargets();
    let pingTargets = [];
    const pingState = {};
    const maxPoints = 36;
    let editingIndex = null;

    const modal = document.getElementById("pingModalBackdrop");
    const openModalBtn = document.getElementById("openPingModal");
    const closeModalBtn = document.getElementById("closePingModal");
    const saveTargetBtn = document.getElementById("saveTarget");
    const cancelEditBtn = document.getElementById("cancelEdit");
    const targetNameInput = document.getElementById("targetName");
    const targetHostInput = document.getElementById("targetHost");
    const customTargetList = document.getElementById("customTargetList");
    const pingStatusState = {};
    const soundSettingsStorageKey = "gateway_ping_sound_settings_v1";
    const openPasswordChangeBtn = document.getElementById("openPasswordChange");
    const openNotificationsBtn = document.getElementById("openNotifications");
    const openUsersManagementBtn = document.getElementById("openUsersManagement");
    const openCarouselSettingsBtn = document.getElementById("openCarouselSettings");
    const soundModal = document.getElementById("soundModalBackdrop");
    const soundModalTitle = document.getElementById("soundModalTitle");
    const closeSoundModalBtn = document.getElementById("closeSoundModal");
    const soundEnabledInput = document.getElementById("soundEnabled");
    const customSoundFileInput = document.getElementById("customSoundFile");
    const saveSoundBtn = document.getElementById("saveSoundBtn");
    const resetSoundBtn = document.getElementById("resetSoundBtn");
    const testSoundBtn = document.getElementById("testSoundBtn");
    const changePasswordBtn = document.getElementById("changePasswordBtn");
    const logoutBtn = document.getElementById("logoutBtn");
    const topLogoutBtn = document.getElementById("topLogoutBtn");
    const topUserName = document.getElementById("topUserName");
    const oldPasswordInput = document.getElementById("oldPassword");
    const newPasswordInput = document.getElementById("newPassword");
    const currentUserLabel = document.getElementById("currentUserLabel");
    const bohdanCarouselSection = document.getElementById("bohdanCarouselSection");
    const adminUsersSection = document.getElementById("adminUsersSection");
    const pendingUsersList = document.getElementById("pendingUsersList");
    const adminUsersList = document.getElementById("adminUsersList");
    const carouselUploadInput = document.getElementById("carouselUploadInput");
    const uploadCarouselImagesBtn = document.getElementById("uploadCarouselImagesBtn");
    const carouselThumbs = document.getElementById("carouselThumbs");
    const secretCarouselToggle = document.getElementById("secretCarouselToggle");
    const alertsFrame = document.getElementById("alertsFrame");
    const carouselStage = document.getElementById("carouselStage");
    const zhytomyrAlertReason = document.getElementById("zhytomyrAlertReason");
    const pingAlertToast = document.getElementById("pingAlertToast");
    const calendarWeekdays = document.getElementById("calendarWeekdays");
    const calendarGrid = document.getElementById("calendarGrid");
    const calendarMonthLabel = document.getElementById("calendarMonthLabel");
    const calendarNextControl = document.getElementById("calendarNextControl");
    const calendarPrevMonth = document.getElementById("calendarPrevMonth");
    const calendarNextMonth = document.getElementById("calendarNextMonth");
    const calendarModal = document.getElementById("calendarModalBackdrop");
    const calendarControlDateInput = document.getElementById("calendarControlDate");
    const calendarControlNameInput = document.getElementById("calendarControlName");
    const calendarSaveBtn = document.getElementById("calendarSaveBtn");
    const calendarDeleteBtn = document.getElementById("calendarDeleteBtn");
    const calendarCloseBtn = document.getElementById("calendarCloseBtn");
    const calendarWeekdayNames = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"];
    const calendarMonthNames = ["Січень", "Лютий", "Березень", "Квітень", "Травень", "Червень", "Липень", "Серпень", "Вересень", "Жовтень", "Листопад", "Грудень"];
    let soundSettings = loadSoundSettings();
    let authMe = null;
    let carouselItems = [];
    let carouselIndex = 0;
    let carouselTimer = null;
    let carouselEnabled = false;
    let calendarCurrentView = new Date();
    let calendarControls = {};
    let calendarStorageKey = null;
    let selectedCalendarDate = null;
    function makeUserActionButton(label, className, onClick) {
      const btn = document.createElement("button");
      btn.type = "button";
      if (className) btn.className = className;
      btn.textContent = label;
      btn.addEventListener("click", onClick);
      return btn;
    }

    async function loadAdminUsers() {
      if (!authMe?.is_admin || !adminUsersSection) return;
      const r = await fetch("/api/admin/users", { cache: "no-store" });
      if (!r.ok) {
        pendingUsersList.innerHTML = "<div class='custom-item-meta'>Не вдалося завантажити заявки.</div>";
        adminUsersList.innerHTML = "<div class='custom-item-meta'>Не вдалося завантажити користувачів.</div>";
        return;
      }
      const payload = await r.json();
      const pending = Array.isArray(payload.pending_users) ? payload.pending_users : [];
      const users = Array.isArray(payload.users) ? payload.users : [];

      pendingUsersList.innerHTML = "";
      if (!pending.length) {
        pendingUsersList.innerHTML = "<div class='custom-item-meta'>Заявок немає.</div>";
      } else {
        pending.forEach((item) => {
          const row = document.createElement("div");
          row.className = "custom-item";
          const info = document.createElement("div");
          info.innerHTML = `<strong>${item.username}</strong>`;
          const actions = document.createElement("div");
          actions.className = "custom-item-actions";
          actions.appendChild(makeUserActionButton("Додати", "", async () => {
            const addResp = await fetch("/api/admin/users/approve", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ pending_user_id: item.id }),
            });
            if (!addResp.ok) {
              alert("Не вдалося погодити заявку.");
              return;
            }
            await loadAdminUsers();
          }));
          row.appendChild(info);
          row.appendChild(actions);
          pendingUsersList.appendChild(row);
        });
      }

      adminUsersList.innerHTML = "";
      users.forEach((item) => {
        const row = document.createElement("div");
        row.className = "custom-item";
        const info = document.createElement("div");
        info.innerHTML = `<strong>${item.username}</strong><div class="custom-item-meta">${item.is_admin ? "Адмін" : "Користувач"}</div>`;
        const actions = document.createElement("div");
        actions.className = "custom-item-actions";

        actions.appendChild(makeUserActionButton("Видалити", "delete", async () => {
          if (!confirm(`Видалити користувача ${item.username}?`)) return;
          const delResp = await fetch(`/api/admin/users/${item.id}`, { method: "DELETE" });
          if (!delResp.ok) {
            alert("Не вдалося видалити користувача.");
            return;
          }
          await loadAdminUsers();
        }));

        if (!item.is_admin) {
          actions.appendChild(makeUserActionButton("Передати права", "", async () => {
            if (!confirm(`Передати права адміна користувачу ${item.username}?`)) return;
            const grantResp = await fetch(`/api/admin/users/${item.id}/transfer-admin`, { method: "POST" });
            if (!grantResp.ok) {
              alert("Не вдалося передати права.");
              return;
            }
            alert("Права адміна передано. Необхідно увійти повторно.");
            await fetch("/api/auth/logout", { method: "POST" });
            window.location.href = "/login";
          }));
        }

        row.appendChild(info);
        row.appendChild(actions);
        adminUsersList.appendChild(row);
      });
    }
    
    function normalizeHost(value) {
      return value.trim();
    }

    function isIPv4(host) {
      const parts = host.split(".");
      if (parts.length !== 4) return false;
      return parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
    }

    function isHostValid(host) {
      return isIPv4(host);
    }

    function loadCustomTargets() {
      try {
        const raw = localStorage.getItem(storageKey);
        if (!raw) return [];
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return [];

        return parsed
          .filter((item) => item && typeof item.name === "string" && typeof item.host === "string")
          .map((item) => ({
            name: item.name.trim().slice(0, 60),
            host: normalizeHost(item.host).slice(0, 64),
          }))
          .filter((item) => item.name && isHostValid(item.host));
      } catch (_err) {
        return [];
      }
    }

    function persistCustomTargets() {
      localStorage.setItem(storageKey, JSON.stringify(customTargets));
    }

    function computePingTargets() {
      pingTargets = [...defaultPingTargets, ...customTargets];
    }

    function createPingCard(target) {
      const wrapper = document.createElement("div");
      wrapper.className = "ping-card";

      const title = document.createElement("div");
      title.className = "ping-title";
      title.textContent = target.name;

      const meta = document.createElement("div");
      meta.className = "ping-meta";
      meta.textContent = `${target.host} • очікування...`;

      const canvas = document.createElement("canvas");
      canvas.width = 250;
      canvas.height = 72;

      wrapper.appendChild(title);
      wrapper.appendChild(meta);
      wrapper.appendChild(canvas);

      pingState[target.host] = {
        meta,
        canvas,
        values: [],
      };
      return wrapper;
    }

    function drawChart(host) {
      const state = pingState[host];
      if (!state) return;
      const ctx = state.canvas.getContext("2d");
      const w = state.canvas.width;
      const h = state.canvas.height;
      ctx.clearRect(0, 0, w, h);

      ctx.strokeStyle = "#1e293b";
      ctx.lineWidth = 1;
      for (let y = 1; y <= 3; y++) {
        const yy = (h / 4) * y;
        ctx.beginPath();
        ctx.moveTo(0, yy);
        ctx.lineTo(w, yy);
        ctx.stroke();
      }

      const vals = state.values;
      if (!vals.length) return;
      const existing = vals.filter((v) => v !== null);
      const maxVal = Math.max(10, ...(existing.length ? existing : [10]));

      ctx.beginPath();
      ctx.lineWidth = 2;
      ctx.strokeStyle = "#60a5fa";

      vals.forEach((val, idx) => {
        const x = (w / (maxPoints - 1)) * idx;
        const y = val === null ? h - 2 : h - (Math.min(val, maxVal) / maxVal) * (h - 4) - 2;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    function mountPingCards() {
      const grid = document.getElementById("pingGrid");
      grid.innerHTML = "";
      Object.keys(pingState).forEach((k) => delete pingState[k]);
      pingTargets.forEach((target) => grid.appendChild(createPingCard(target)));
    }

    function pushValue(host, ms) {
      const state = pingState[host];
      if (!state) return;
      state.values.push(ms);
      if (state.values.length > maxPoints) {
        state.values.shift();
      }
      drawChart(host);
    }

    async function refreshPing() {
      const hosts = pingTargets.map((target) => target.host);
      try {
        const r = await fetch("/api/ping", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          cache: "no-store",
          body: JSON.stringify({ hosts }),
        });
        const payload = await r.json();

        pingTargets.forEach((target) => {
          const sample = payload.results[target.host];
          if (!sample || !sample.ok) {
            pingState[target.host].meta.innerHTML = `${target.host} • <span class="down">offline</span>`;
            pushValue(target.host, null);
            handlePingStatusChange(target, false);
            return;
          }

          pingState[target.host].meta.textContent = `${target.host} • ${sample.ms.toFixed(1)} ms`;
          pushValue(target.host, sample.ms);
          handlePingStatusChange(target, true);
        });
      } catch (_err) {
        pingTargets.forEach((target) => {
          pingState[target.host].meta.innerHTML = `${target.host} • <span class="down">дані недоступні</span>`;
          pushValue(target.host, null);
          handlePingStatusChange(target, false);
        });
      }
    }

    function loadSoundSettings() {
      try {
        const raw = localStorage.getItem(soundSettingsStorageKey);
        if (!raw) return { enabled: true, customDataUrl: null };
        const parsed = JSON.parse(raw);
        return {
          enabled: parsed?.enabled !== false,
          customDataUrl: typeof parsed?.customDataUrl === "string" ? parsed.customDataUrl : null,
        };
      } catch (_err) {
        return { enabled: true, customDataUrl: null };
      }
    }

    function persistSoundSettings() {
      localStorage.setItem(soundSettingsStorageKey, JSON.stringify(soundSettings));
    }

    function showPingAlert(message) {
      pingAlertToast.textContent = message;
      pingAlertToast.classList.add("show");
      setTimeout(() => pingAlertToast.classList.remove("show"), 4000);
    }

    function playDefaultBeep() {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = "sine";
      osc.frequency.value = 880;
      gain.gain.value = 0.12;
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.24);
    }

    function playAlertSound() {
      if (!soundSettings.enabled) return;
      try {
        if (soundSettings.customDataUrl) {
          const audio = new Audio(soundSettings.customDataUrl);
          audio.volume = 0.8;
          audio.play().catch(() => playDefaultBeep());
          return;
        }
        playDefaultBeep();
      } catch (_err) {
        playDefaultBeep();
      }
    }

    function notifyBrowser(message) {
      if (!("Notification" in window)) return;
      if (Notification.permission === "granted") {
        new Notification("Gateway Ping Alert", { body: message });
      } else if (Notification.permission === "default") {
        Notification.requestPermission().then((perm) => {
          if (perm === "granted") new Notification("Gateway Ping Alert", { body: message });
        }).catch(() => {});
      }
    }

    function handlePingStatusChange(target, isUp) {
      const prev = pingStatusState[target.host];
      pingStatusState[target.host] = isUp ? "up" : "down";
      if (prev === "up" && !isUp) {
        const message = `Увага: ${target.name} (${target.host}) недоступний`;
        showPingAlert(message);
        playAlertSound();
        notifyBrowser(message);
      }
    }

    function openModal() {
      modal.classList.add("open");
      targetNameInput.focus();
    }

    function closeModal() {
      modal.classList.remove("open");
      resetForm();
    }

    function resetForm() {
      editingIndex = null;
      targetNameInput.value = "";
      targetHostInput.value = "";
    }

    function renderCustomTargetList() {
      customTargetList.innerHTML = "";
      if (!customTargets.length) {
        const empty = document.createElement("div");
        empty.className = "custom-item-meta";
        empty.textContent = "Ще немає доданих цілей.";
        customTargetList.appendChild(empty);
        return;
      }

      customTargets.forEach((target, idx) => {
        const item = document.createElement("div");
        item.className = "custom-item";

        const info = document.createElement("div");
        info.innerHTML = `<strong>${target.name}</strong><div class="custom-item-meta">${target.host}</div>`;

        const actions = document.createElement("div");
        actions.className = "custom-item-actions";

        const editBtn = document.createElement("button");
        editBtn.type = "button";
        editBtn.textContent = "Редагувати";
        editBtn.addEventListener("click", () => {
          editingIndex = idx;
          targetNameInput.value = target.name;
          targetHostInput.value = target.host;
          targetNameInput.focus();
        });

        const deleteBtn = document.createElement("button");
        deleteBtn.type = "button";
        deleteBtn.className = "delete";
        deleteBtn.textContent = "Видалити";
        deleteBtn.addEventListener("click", () => {
          customTargets.splice(idx, 1);
          persistCustomTargets();
          rebuildTargetsAndCards();
          renderCustomTargetList();
          if (editingIndex === idx) resetForm();
        });

        actions.appendChild(editBtn);
        actions.appendChild(deleteBtn);
        item.appendChild(info);
        item.appendChild(actions);
        customTargetList.appendChild(item);
      });
    }

    function saveCustomTarget() {
      const name = targetNameInput.value.trim();
      const host = normalizeHost(targetHostInput.value);
      if (!name || !host) {
        alert("Введіть назву та IP-адресу.");
        return;
      }
      if (!isHostValid(host)) {
        alert("Введіть коректну IPv4-адресу (напр. 192.168.1.10).");
        return;
      }

      const duplicateIdx = customTargets.findIndex((item, idx) => item.host === host && idx !== editingIndex);
      if (duplicateIdx !== -1) {
        alert("Ця IP-адреса вже додана.");
        return;
      }

      const entry = { name: name.slice(0, 60), host: host.slice(0, 64) };
      if (editingIndex === null) customTargets.push(entry);
      else customTargets[editingIndex] = entry;

      persistCustomTargets();
      rebuildTargetsAndCards();
      renderCustomTargetList();
      resetForm();
    }

    function rebuildTargetsAndCards() {
      computePingTargets();
      mountPingCards();
      refreshPing();
    }

    function formatDateKey(dateObj) {
      const y = dateObj.getFullYear();
      const m = String(dateObj.getMonth() + 1).padStart(2, "0");
      const d = String(dateObj.getDate()).padStart(2, "0");
      return `${y}-${m}-${d}`;
    }

    function formatCalendarHumanDate(dateKey) {
      const [year, month, day] = dateKey.split("-");
      return `${day}.${month}.${year}`;
    }

    function loadCalendarControls() {
      if (!calendarStorageKey) return;
      try {
        const raw = localStorage.getItem(calendarStorageKey);
        if (!raw) {
          calendarControls = {};
          return;
        }
        const parsed = JSON.parse(raw);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
          calendarControls = {};
          return;
        }
        calendarControls = Object.entries(parsed).reduce((acc, [key, value]) => {
          if (/^\d{4}-\d{2}-\d{2}$/.test(key) && typeof value === "string" && value.trim()) {
            acc[key] = value.trim().slice(0, 120);
          }
          return acc;
        }, {});
      } catch (_err) {
        calendarControls = {};
      }
    }

    function persistCalendarControls() {
      if (!calendarStorageKey) return;
      localStorage.setItem(calendarStorageKey, JSON.stringify(calendarControls));
    }

    function renderCalendarWeekdays() {
      if (!calendarWeekdays) return;
      calendarWeekdays.innerHTML = "";
      calendarWeekdayNames.forEach((name) => {
        const cell = document.createElement("div");
        cell.className = "calendar-weekday";
        cell.textContent = name;
        calendarWeekdays.appendChild(cell);
      });
    }

    function openCalendarModal(dateKey) {
      selectedCalendarDate = dateKey;
      calendarControlDateInput.value = formatCalendarHumanDate(dateKey);
      calendarControlNameInput.value = calendarControls[dateKey] || "";
      calendarDeleteBtn.style.display = calendarControls[dateKey] ? "inline-block" : "none";
      calendarModal.classList.add("open");
      calendarControlNameInput.focus();
    }

    function closeCalendarModal() {
      calendarModal.classList.remove("open");
      selectedCalendarDate = null;
      calendarControlNameInput.value = "";
    }

    function renderCalendar() {
      if (!calendarGrid || !calendarMonthLabel) return;
      const year = calendarCurrentView.getFullYear();
      const month = calendarCurrentView.getMonth();
      calendarMonthLabel.textContent = `${calendarMonthNames[month]} ${year}`;
      calendarGrid.innerHTML = "";
      const now = new Date();
      const todayKey = formatDateKey(new Date(now.getFullYear(), now.getMonth(), now.getDate()));

      const firstDay = new Date(year, month, 1);
      const daysInMonth = new Date(year, month + 1, 0).getDate();
      const leadEmpty = (firstDay.getDay() + 6) % 7;

      for (let i = 0; i < leadEmpty; i++) {
        const emptyCell = document.createElement("button");
        emptyCell.type = "button";
        emptyCell.className = "calendar-day muted";
        emptyCell.disabled = true;
        calendarGrid.appendChild(emptyCell);
      }

      for (let day = 1; day <= daysInMonth; day++) {
        const dateObj = new Date(year, month, day);
        const dateKey = formatDateKey(dateObj);
        const controlText = calendarControls[dateKey];
        const cell = document.createElement("button");
        cell.type = "button";
        const isToday = dateKey === todayKey;
        cell.className = `calendar-day${controlText ? " has-control" : ""}${isToday ? " today" : ""}`;
        cell.innerHTML = `<span class="calendar-day-label">${day}</span>${controlText ? `<span class="calendar-day-note">${controlText}</span>` : ""}`;
        cell.addEventListener("click", () => openCalendarModal(dateKey));
        calendarGrid.appendChild(cell);
      }
      renderNextControlInfo();
    }

    function renderNextControlInfo() {
      if (!calendarNextControl) return;
      const today = formatDateKey(new Date());
      const nextDate = Object.keys(calendarControls)
        .filter((key) => key >= today && typeof calendarControls[key] === "string" && calendarControls[key].trim())
        .sort()[0];

      if (!nextDate) {
        calendarNextControl.innerHTML = "<strong>Дата наступного контролю:</strong> не заплановано";
        return;
      }
      const controlName = calendarControls[nextDate];
      calendarNextControl.innerHTML = `<strong>Дата наступного контролю:</strong> ${formatCalendarHumanDate(nextDate)} — ${controlName}`;
    }

    function saveCalendarControl() {
      if (!selectedCalendarDate) return;
      const value = calendarControlNameInput.value.trim();
      if (!value) {
        alert("Введіть назву контролю або натисніть «Видалити».");
        return;
      }
      calendarControls[selectedCalendarDate] = value.slice(0, 120);
      persistCalendarControls();
      renderCalendar();
      closeCalendarModal();
    }

    function deleteCalendarControl() {
      if (!selectedCalendarDate) return;
      if (!calendarControls[selectedCalendarDate]) {
        closeCalendarModal();
        return;
      }
      delete calendarControls[selectedCalendarDate];
      persistCalendarControls();
      renderCalendar();
      closeCalendarModal();
    }

    function setupCalendarForCurrentUser() {
      if (!authMe?.username) return;
      calendarStorageKey = `gateway_calendar_controls_v1_${authMe.username}`;
      loadCalendarControls();
      renderCalendarWeekdays();
      renderCalendar();
    }

    openModalBtn.addEventListener("click", () => {
      renderCustomTargetList();
      openModal();
    });

    closeModalBtn.addEventListener("click", closeModal);
    cancelEditBtn.addEventListener("click", resetForm);
    saveTargetBtn.addEventListener("click", saveCustomTarget);

    modal.addEventListener("click", (event) => {
      if (event.target === modal) closeModal();
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && modal.classList.contains("open")) closeModal();
      if (event.key === "Escape" && calendarModal.classList.contains("open")) closeCalendarModal();
    });

    calendarPrevMonth.addEventListener("click", () => {
      calendarCurrentView = new Date(calendarCurrentView.getFullYear(), calendarCurrentView.getMonth() - 1, 1);
      renderCalendar();
    });
    calendarNextMonth.addEventListener("click", () => {
      calendarCurrentView = new Date(calendarCurrentView.getFullYear(), calendarCurrentView.getMonth() + 1, 1);
      renderCalendar();
    });
    calendarSaveBtn.addEventListener("click", saveCalendarControl);
    calendarDeleteBtn.addEventListener("click", deleteCalendarControl);
    calendarCloseBtn.addEventListener("click", closeCalendarModal);
    calendarModal.addEventListener("click", (event) => {
      if (event.target === calendarModal) closeCalendarModal();
    });

    function showCarouselSlide(index) {
      if (!carouselStage) return;
      const images = carouselStage.querySelectorAll(".carousel-image");
      if (!images.length) return;
      images.forEach((img, idx) => img.classList.toggle("visible", idx === index));
    }

    function renderCarouselImages() {
      if (!carouselStage) return;
      carouselStage.innerHTML = "";
      carouselItems.forEach((item, idx) => {
        const img = document.createElement("img");
        img.className = "carousel-image";
        img.src = item.url;
        img.alt = `carousel-${idx + 1}`;
        carouselStage.appendChild(img);
      });
      carouselIndex = 0;
      showCarouselSlide(0);
    }

    function renderCarouselThumbs() {
      if (!carouselThumbs) return;
      carouselThumbs.innerHTML = "";
      carouselItems.forEach((item) => {
        const box = document.createElement("div");
        box.className = "carousel-thumb-item";
        const img = document.createElement("img");
        img.src = item.url;
        img.alt = "thumb";
        const del = document.createElement("button");
        del.type = "button";
        del.className = "carousel-thumb-delete";
        del.textContent = "×";
        del.addEventListener("click", async () => {
          if (!confirm("Видалити це фото з каруселі?")) return;
          const r = await fetch(`/api/carousel/images/${item.id}`, { method: "DELETE" });
          if (!r.ok) {
            alert("Не вдалося видалити фото.");
            return;
          }
          await loadCarouselImages();
        });
        box.appendChild(img);
        box.appendChild(del);
        carouselThumbs.appendChild(box);
      });
    }

    function startCarousel() {
      if (carouselTimer) clearInterval(carouselTimer);
      if (carouselItems.length <= 1) return;
      carouselTimer = setInterval(() => {
        carouselIndex = (carouselIndex + 1) % carouselItems.length;
        showCarouselSlide(carouselIndex);
      }, 30000);
    }

    async function loadCarouselImages() {
      if (!secretCarouselToggle) return;
      const r = await fetch("/api/carousel/images", { cache: "no-store" });
      if (!r.ok) return;
      const payload = await r.json();
      carouselItems = Array.isArray(payload.items) ? payload.items : [];
      renderCarouselImages();
      renderCarouselThumbs();
      startCarousel();
    }

    function setCarouselEnabled(enabled) {
      if (!alertsFrame || !carouselStage) return;
      carouselEnabled = enabled;
      alertsFrame.style.display = enabled ? "none" : "block";
      carouselStage.classList.toggle("active", enabled);
      if (enabled) startCarousel();
    }

    async function refreshZhytomyrAlertReason() {
      if (!zhytomyrAlertReason) return;
      try {
        const r = await fetch("/api/alerts/zhytomyr-cause", { cache: "no-store" });
        if (!r.ok) return;
        const payload = await r.json();
        if (payload.active) {
          zhytomyrAlertReason.textContent = `Житомирська область: ${payload.reason}`;
          zhytomyrAlertReason.style.display = "block";
        } else {
          zhytomyrAlertReason.style.display = "none";
          zhytomyrAlertReason.textContent = "";
        }
      } catch (_err) {
        zhytomyrAlertReason.style.display = "none";
      }
    }

    async function fetchMe() {
      const r = await fetch("/api/auth/me", { cache: "no-store" });
      if (!r.ok) {
        window.location.href = "/login";
        return null;
      }
      authMe = await r.json();
      currentUserLabel.textContent = authMe.username;
      if (topUserName) topUserName.textContent = authMe.username;
      if (openCarouselSettingsBtn) {
        openCarouselSettingsBtn.style.display = authMe.username === "Богдан" ? "inline-grid" : "none";
      }
      if (openUsersManagementBtn) {
        openUsersManagementBtn.style.display = authMe.is_admin ? "inline-grid" : "none";
      }
      if (bohdanCarouselSection) {
        bohdanCarouselSection.style.display = authMe.username === "Богдан" ? "block" : "none";
      }
      if (adminUsersSection) {
        adminUsersSection.style.display = authMe.is_admin ? "block" : "none";
      }
      return authMe;
    }

    function openSoundSettingsModal(mode = "all") {
      soundEnabledInput.checked = soundSettings.enabled;
      customSoundFileInput.value = "";
      oldPasswordInput.value = "";
      newPasswordInput.value = "";
      const passwordOnly = mode === "password";
      const notificationsOnly = mode === "notifications";
      const usersOnly = mode === "users";
      const carouselOnly = mode === "carousel";
      soundModal.classList.toggle("password-only", passwordOnly);
      soundModal.classList.toggle("notifications-only", notificationsOnly);
      soundModal.classList.toggle("users-only", usersOnly);
      soundModal.classList.toggle("carousel-only", carouselOnly);
      if (passwordOnly) {
        soundModalTitle.textContent = "Зміна паролю";
      } else if (notificationsOnly) {
        soundModalTitle.textContent = "Сповіщення";
      } else if (usersOnly) {
        soundModalTitle.textContent = "Користувачі";
      } else if (carouselOnly) {
        soundModalTitle.textContent = "Карусель";
      } else {
        soundModalTitle.textContent = "Налаштування";
      }
      soundModal.classList.add("open");
      fetchMe().then((me) => {
        if (mode === "all" || mode === "users") loadAdminUsers();
        if (mode === "users" && !me?.is_admin) {
          alert("Цей розділ доступний лише адміну.");
          soundModal.classList.remove("open");
          soundModal.classList.remove("users-only");
        }
        if (mode === "carousel" && me?.username !== "Богдан") {
          alert("Цей розділ доступний лише Богдану.");
          soundModal.classList.remove("open");
          soundModal.classList.remove("carousel-only");
        }
      });
    }

    openPasswordChangeBtn.addEventListener("click", () => openSoundSettingsModal("password"));
    openNotificationsBtn.addEventListener("click", () => openSoundSettingsModal("notifications"));
    openUsersManagementBtn.addEventListener("click", () => openSoundSettingsModal("users"));
    openCarouselSettingsBtn.addEventListener("click", () => openSoundSettingsModal("carousel"));
    closeSoundModalBtn.addEventListener("click", () => {
      soundModal.classList.remove("open");
      soundModal.classList.remove("password-only");
      soundModal.classList.remove("notifications-only");
      soundModal.classList.remove("users-only");
      soundModal.classList.remove("carousel-only");
    });
    soundModal.addEventListener("click", (event) => {
      if (event.target === soundModal) {
        soundModal.classList.remove("open");
        soundModal.classList.remove("password-only");
        soundModal.classList.remove("notifications-only");
        soundModal.classList.remove("users-only");
        soundModal.classList.remove("carousel-only");
      }
    });
    testSoundBtn.addEventListener("click", playAlertSound);
    changePasswordBtn.addEventListener("click", async () => {
      const oldPassword = oldPasswordInput.value;
      const newPassword = newPasswordInput.value;
      const r = await fetch("/api/users/change-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
      });
      if (!r.ok) {
        alert("Не вдалося змінити пароль.");
        return;
      }
      oldPasswordInput.value = "";
      newPasswordInput.value = "";
      alert("Пароль змінено.");
    });
    logoutBtn.addEventListener("click", async () => {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.href = "/login";
    });
    if (topLogoutBtn) {
      topLogoutBtn.addEventListener("click", async () => {
        await fetch("/api/auth/logout", { method: "POST" });
        window.location.href = "/login";
      });
    }
    if (secretCarouselToggle) {
      secretCarouselToggle.addEventListener("click", () => {
        if (carouselItems.length === 0) {
          alert("Карусель порожня. Спочатку завантажте фото в налаштуваннях.");
          return;
        }
        setCarouselEnabled(!carouselEnabled);
      });
    }
    if (uploadCarouselImagesBtn) {
      uploadCarouselImagesBtn.addEventListener("click", async () => {
        if (authMe?.username !== "Богдан") return;
        const files = carouselUploadInput.files;
        if (!files || !files.length) {
          alert("Оберіть фото для завантаження.");
          return;
        }
        const formData = new FormData();
        Array.from(files).forEach((file) => formData.append("images", file));
        const r = await fetch("/api/carousel/images", { method: "POST", body: formData });
        if (!r.ok) {
          alert("Не вдалося завантажити фото.");
          return;
        }
        carouselUploadInput.value = "";
        await loadCarouselImages();
        alert("Фото завантажено.");
      });
    }
    resetSoundBtn.addEventListener("click", () => {
      soundSettings = { enabled: true, customDataUrl: null };
      persistSoundSettings();
      soundEnabledInput.checked = true;
      customSoundFileInput.value = "";
      alert("Налаштування звуку скинуто.");
    });
    saveSoundBtn.addEventListener("click", () => {
      soundSettings.enabled = soundEnabledInput.checked;
      const file = customSoundFileInput.files && customSoundFileInput.files[0];
      if (!file) {
        persistSoundSettings();
        soundModal.classList.remove("open");
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        soundSettings.customDataUrl = typeof reader.result === "string" ? reader.result : null;
        persistSoundSettings();
        soundModal.classList.remove("open");
      };
      reader.onerror = () => {
        alert("Не вдалося прочитати аудіо файл.");
      };
      reader.readAsDataURL(file);
    });

     fetchMe().then((me) => {
      setupCalendarForCurrentUser();
      if (me?.username === "Богдан") {
        loadCarouselImages();
      }
    });
    refreshZhytomyrAlertReason();
    setInterval(refreshZhytomyrAlertReason, 30000);
    computePingTargets();
    mountPingCards();
    refreshPing();
    setInterval(refreshPing, 2000);

    persistSoundSettings();
  </script>
</body>
</html>
"""


def _db_conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_auth_storage() -> None:
    CAROUSEL_DIR.mkdir(parents=True, exist_ok=True)
    with _db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS carousel_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT UNIQUE NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                requested_at INTEGER NOT NULL
            )
            """
        )
        exists = conn.execute("SELECT id FROM users WHERE username = ?", ("Богдан",)).fetchone()
        if exists is None:
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                ("Богдан", generate_password_hash(DEFAULT_PASSWORD)),
            )
        conn.commit()


def _current_user() -> Optional[sqlite3.Row]:
    uid = session.get("user_id")
    if not uid:
        return None
    with _db_conn() as conn:
        return conn.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (uid,)).fetchone()


def _require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if _current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)

    return wrapped


def _require_admin(view):
    @wraps(view)
    @_require_login
    def wrapped(*args, **kwargs):
        user = _current_user()
        if user is None or not bool(user["is_admin"]):
            return jsonify({"error": "forbidden"}), 403
        return view(*args, **kwargs)

    return wrapped


def _find_logo_file() -> Optional[Path]:
    if not LOGO_DIR.exists():
        return None
    for ext in LOGO_EXTENSIONS:
        files = sorted(LOGO_DIR.glob(f"*{ext}"))
        if files:
            return files[0]
    return None


@app.route("/")
@_require_login
def index():
    user = _current_user()
    gateway_host = request.host.split(":")[0]
    items = [{"name": name, "url": f"http://{gateway_host}:{port}"} for name, _, port in TARGET_APPS]
    external_items = [
        {"name": name, "url": url, "icon": _resolve_icon_url(name, icon)}
        for name, url, icon in EXTERNAL_LINKS
    ]
    gateway_url = f"http://{gateway_host}:{GATEWAY_PORT}"
    ping_targets = [{"name": name, "host": host} for name, host in PING_TARGETS]
    return render_template_string(
        PAGE_TEMPLATE,
        items=items,
        external_items=external_items,
        gateway_url=gateway_url,
        ping_targets=ping_targets,
        is_bohdan=bool(user and user["username"] == "Богдан"),
    )


@app.route("/login")
def login_page():
    if _current_user() is not None:
        return redirect(url_for("index"))
    logo_file = _find_logo_file()
    logo_url = url_for("logo_file", filename=logo_file.name) if logo_file else None
    return render_template_string(LOGIN_TEMPLATE, logo_url=logo_url)


@app.route("/logo/<path:filename>")
def logo_file(filename: str):
    return send_from_directory(LOGO_DIR, filename)


@app.route("/api/auth/login", methods=["POST"])
def auth_login_api():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    with _db_conn() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash, is_admin FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401
    session["user_id"] = user["id"]
    return jsonify({"ok": True})


@app.route("/api/auth/register", methods=["POST"])
def auth_register_api():
    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    password = payload.get("password") or ""
    if len(username) < 3 or len(password) < 4:
        return jsonify({"error": "invalid payload"}), 400
    with _db_conn() as conn:
        in_users = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        in_pending = conn.execute("SELECT id FROM pending_users WHERE username = ?", (username,)).fetchone()
        if in_users is not None or in_pending is not None:
            return jsonify({"error": "username exists"}), 409
        conn.execute(
            "INSERT INTO pending_users (username, password_hash, requested_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), int(time.time())),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout_api():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/auth/me", methods=["GET"])
@_require_login
def auth_me_api():
    user = _current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"id": user["id"], "username": user["username"], "is_admin": bool(user["is_admin"])})


@app.route("/api/users/change-password", methods=["POST"])
@_require_login
def change_password_api():
    user = _current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    old_password = payload.get("old_password") or ""
    new_password = payload.get("new_password") or ""
    if len(new_password) < 4:
        return jsonify({"error": "new password too short"}), 400
    with _db_conn() as conn:
        current = conn.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if current is None or not check_password_hash(current["password_hash"], old_password):
            return jsonify({"error": "old password invalid"}), 400
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/users", methods=["GET"])
@_require_admin
def admin_users_list_api():
    current = _current_user()
    with _db_conn() as conn:
        pending_rows = conn.execute(
            "SELECT id, username, requested_at FROM pending_users ORDER BY requested_at ASC"
        ).fetchall()
        user_rows = conn.execute(
            "SELECT id, username, is_admin FROM users ORDER BY username COLLATE NOCASE ASC"
        ).fetchall()
    return jsonify(
        {
            "pending_users": [
                {"id": row["id"], "username": row["username"], "requested_at": row["requested_at"]}
                for row in pending_rows
            ],
            "users": [
                {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"]), "is_me": bool(current and current["id"] == row["id"])}
                for row in user_rows
            ],
        }
    )


@app.route("/api/admin/users/approve", methods=["POST"])
@_require_admin
def admin_users_approve_api():
    payload = request.get_json(silent=True) or {}
    pending_user_id = payload.get("pending_user_id")
    if not isinstance(pending_user_id, int):
        return jsonify({"error": "pending_user_id required"}), 400
    with _db_conn() as conn:
        pending = conn.execute(
            "SELECT id, username, password_hash FROM pending_users WHERE id = ?",
            (pending_user_id,),
        ).fetchone()
        if pending is None:
            return jsonify({"error": "pending user not found"}), 404
        exists = conn.execute("SELECT id FROM users WHERE username = ?", (pending["username"],)).fetchone()
        if exists is not None:
            conn.execute("DELETE FROM pending_users WHERE id = ?", (pending_user_id,))
            conn.commit()
            return jsonify({"error": "username exists"}), 409
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)",
            (pending["username"], pending["password_hash"]),
        )
        conn.execute("DELETE FROM pending_users WHERE id = ?", (pending_user_id,))
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@_require_admin
def admin_users_delete_api(user_id: int):
    current = _current_user()
    if current is None:
        return jsonify({"error": "unauthorized"}), 401
    if current["id"] == user_id:
        return jsonify({"error": "cannot delete yourself"}), 400
    with _db_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>/transfer-admin", methods=["POST"])
@_require_admin
def admin_users_transfer_admin_api(user_id: int):
    current = _current_user()
    if current is None:
        return jsonify({"error": "unauthorized"}), 401
    if current["id"] == user_id:
        return jsonify({"error": "already admin"}), 400
    with _db_conn() as conn:
        target = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            return jsonify({"error": "not found"}), 404
        conn.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (current["id"],))
        conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
        conn.commit()
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/carousel/images", methods=["GET", "POST"])
@_require_login
def carousel_images_api():
    user = _current_user()
    if user is None:
        return jsonify({"error": "unauthorized"}), 401

    if request.method == "GET":
        if user["username"] != "Богдан":
            return jsonify({"items": []})
        with _db_conn() as conn:
            rows = conn.execute("SELECT id, file_name FROM carousel_images ORDER BY created_at DESC").fetchall()
        items = [{"id": row["id"], "url": url_for("carousel_image_file_api", file_name=row["file_name"])} for row in rows]
        return jsonify({"items": items})

    if user["username"] != "Богдан":
        return jsonify({"error": "forbidden"}), 403

    files = request.files.getlist("images")
    if not files:
        return jsonify({"error": "images required"}), 400
    saved = 0
    with _db_conn() as conn:
        for file in files:
            if not file or not file.filename:
                continue
            ext = Path(file.filename).suffix.lower()
            if ext not in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
                continue
            name = f"{int(time.time()*1000)}_{os.urandom(4).hex()}{ext}"
            file.save(CAROUSEL_DIR / name)
            conn.execute(
                "INSERT INTO carousel_images (file_name, created_at) VALUES (?, ?)",
                (name, int(time.time())),
            )
            saved += 1
        conn.commit()
    return jsonify({"ok": True, "saved": saved})


@app.route("/api/carousel/images/<int:image_id>", methods=["DELETE"])
@_require_login
def carousel_image_delete_api(image_id: int):
    user = _current_user()
    if user is None or user["username"] != "Богдан":
        return jsonify({"error": "forbidden"}), 403
    with _db_conn() as conn:
        row = conn.execute("SELECT file_name FROM carousel_images WHERE id = ?", (image_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        conn.execute("DELETE FROM carousel_images WHERE id = ?", (image_id,))
        conn.commit()
    path = CAROUSEL_DIR / row["file_name"]
    if path.exists():
        path.unlink()
    return jsonify({"ok": True})

@app.route("/api/carousel/file/<path:file_name>", methods=["GET"])
@_require_login
def carousel_image_file_api(file_name: str):
    user = _current_user()
    if user is None or user["username"] != "Богдан":
        return jsonify({"error": "forbidden"}), 403
    safe_name = Path(file_name).name
    if safe_name != file_name:
        abort(400)
    return send_from_directory(CAROUSEL_DIR, safe_name)

@app.route("/api/alerts/zhytomyr-cause", methods=["GET"])
@_require_login
def zhytomyr_alert_cause_api():
    reason = _fetch_zhytomyr_alert_reason()
    return jsonify({"active": reason is not None, "reason": reason or ""})


@app.route("/api/ping", methods=["GET", "POST"])
@_require_login
def ping_api():
    requested_hosts = _requested_hosts_from_payload()
    targets = requested_hosts or [host for _, host in PING_TARGETS]

    results = {}
    for host in targets:
        ms = _ping_host_ms(host)
        results[host] = {"ok": ms is not None, "ms": ms}
    return jsonify({"ts": int(time.time()), "results": results})


def _fetch_zhytomyr_alert_reason() -> Optional[str]:
    sources = [
        "https://api.alerts.in.ua/v1/alerts/active.json",
        "https://api.alerts.in.ua/v1/iot/active_air_raid_alerts_by_oblast.json",
    ]
    for src in sources:
        try:
            with urllib.request.urlopen(src, timeout=4) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError):
            continue

        reason = _parse_zhytomyr_reason_from_payload(data)
        if reason is not None:
            return reason
    return None


def _parse_zhytomyr_reason_from_payload(payload) -> Optional[str]:
    reason_map = {
        "air_raid": "повітряна тривога (повітряна загроза)",
        "artillery_shelling": "артилерійський обстріл",
        "urban_fights": "вуличні бої",
        "chemical": "хімічна загроза",
        "nuclear": "радіаційна/ядерна загроза",
        "missile": "ракетна загроза",
        "drone": "загроза БпЛА",
    }

    if isinstance(payload, dict):
        # Variant 1: detailed list with region/title/type
        for key in ("alerts", "active_alerts", "states"):
            entries = payload.get(key)
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, dict):
                    continue
                region = str(item.get("region") or item.get("title") or item.get("name") or "").lower()
                if "житомир" not in region:
                    continue
                type_key = str(item.get("type") or item.get("alert_type") or "").lower()
                return reason_map.get(type_key, "невідомо (активна тривога)")

        # Variant 2: iot map by oblast id/name
        for key in ("10", "Житомирська область", "Zhytomyrska oblast", "Житомирська"):
            val = payload.get(key)
            if val in ("A", 1, True, "true", "active"):
                return "повітряна тривога (повітряна загроза)"
    return None


def _requested_hosts_from_payload() -> List[str]:
    if request.method != "POST":
        return []

    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return []

    hosts = payload.get("hosts")
    if not isinstance(hosts, list):
        return []

    cleaned_hosts: List[str] = []
    for host in hosts:
        if not isinstance(host, str):
            continue
        normalized = host.strip()
        if _is_valid_ipv4(normalized):
            cleaned_hosts.append(normalized)

    deduped = list(dict.fromkeys(cleaned_hosts))
    return deduped[:32]


def _is_valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def _resolve_icon_url(service_name: str, fallback_icon: str) -> str:
    key = USER_ICON_KEY_MAP.get(service_name)
    if key:
        for ext in USER_ICON_EXTENSIONS:
            candidate = USER_ICON_DIR / f"{key}{ext}"
            if candidate.exists():
                return url_for("static", filename=f"user-icons/{candidate.name}")
    return url_for("static", filename=fallback_icon)


def _ping_host_ms(host: str) -> Optional[float]:
    commands = [
        ["ping", "-c", "1", "-W", "1", host],
        ["ping", "-n", "1", "-w", "1000", host],
    ]

    for cmd in commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

        output = (result.stdout or "") + "\n" + (result.stderr or "")
        match = re.search(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", output, flags=re.IGNORECASE)
        if not match:
            match = re.search(r"time[=<]\s*([0-9]+(?:[\.,][0-9]+)?)", output, flags=re.IGNORECASE)

        if match:
            value = match.group(1).replace(",", ".")
            try:
                return float(value)
            except ValueError:
                return None
    return None


def _stream_logs(tag: str, process: subprocess.Popen) -> None:
    if process.stdout is None:
        return
    for line in iter(process.stdout.readline, ""):
        if not line:
            break
        print(f"[{tag}] {line.rstrip()}")


def _terminate_all(reason: str = "shutdown") -> None:
    global _shutdown_started
    if _shutdown_started:
        return
    _shutdown_started = True

    print(f"[gateway] Starting graceful shutdown ({reason})...")
    for tag, proc in child_processes.items():
        if proc.poll() is None:
            print(f"[gateway] Terminating {tag} (pid={proc.pid})")
            proc.terminate()

    deadline = time.time() + 6
    for tag, proc in child_processes.items():
        if proc.poll() is not None:
            continue
        timeout = max(0, deadline - time.time())
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            print(f"[gateway] Force killing {tag} (pid={proc.pid})")
            proc.kill()


def _on_signal(sig_num, _frame) -> None:
    signame = signal.Signals(sig_num).name
    _terminate_all(reason=f"signal {signame}")
    os._exit(0)


def start_managed_apps() -> None:
    script_path = Path(__file__).resolve()

    for name, relative_path, port in TARGET_APPS:
        app_path = Path(relative_path).resolve()
        if not app_path.exists():
            print(f"[gateway][warning] {name}: file not found -> {app_path}")
            continue
        if not _is_port_available(GATEWAY_HOST, port):
            print(f"[gateway][error] {name}: port {port} is already in use, skipping startup")
            continue

        python_exec = _pick_python_for_app(app_path)
        cmd = [
            python_exec,
            str(script_path),
            "--run-managed-app",
            str(app_path),
            str(port),
        ]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        child_processes[name] = proc
        print(f"[gateway] {name} started on http://0.0.0.0:{port} (pid={proc.pid}, python={python_exec})")

        log_thread = threading.Thread(
            target=_stream_logs,
            args=(name, proc),
            daemon=True,
        )
        log_thread.start()


def _is_port_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _pick_python_for_app(app_file: Path) -> str:
    app_dir = app_file.parent
    candidates = [
        app_dir / "venv2" / "bin" / "python3",
        app_dir / "venv2" / "bin" / "python",
        app_dir / "venv" / "bin" / "python3",
        app_dir / "venv" / "bin" / "python",
        app_dir / "venv2" / "Scripts" / "python.exe",
        app_dir / "venv" / "Scripts" / "python.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return sys.executable


def _run_managed_app(file_path: str, port: int) -> None:
    app_file = Path(file_path).resolve()
    if not app_file.exists():
        raise FileNotFoundError(f"App file does not exist: {app_file}")
    os.chdir(app_file.parent)

    try:
        module_name = f"managed_{app_file.stem}_{port}"
        spec = importlib.util.spec_from_file_location(module_name, app_file)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot import app module from {app_file}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        flask_app = None
        if hasattr(module, "app") and isinstance(module.app, Flask):
            flask_app = module.app
        else:
            for value in vars(module).values():
                if isinstance(value, Flask):
                    flask_app = value
                    break

        if flask_app is not None:
            print(f"[runner] Launching Flask app from {app_file} on http://0.0.0.0:{port}")
            flask_app.run(host=GATEWAY_HOST, port=port, debug=False, use_reloader=False)
            return

        print(f"[runner][warning] Flask app instance not found in {app_file}, switching to script mode")
        _exec_script_fallback(app_file, port)
    except Exception as exc:
        print(f"[runner][warning] Import/bootstrap failed for {app_file}: {exc}")
        print("[runner][warning] Switching to script mode. Install/fix app dependencies for stable startup.")
        _exec_script_fallback(app_file, port)


def _exec_script_fallback(app_file: Path, port: int) -> None:
    os.chdir(app_file.parent)
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["APP_PORT"] = str(port)
    env["FLASK_RUN_PORT"] = str(port)
    env["HOST"] = GATEWAY_HOST
    env["FLASK_RUN_HOST"] = GATEWAY_HOST
    env["APP_DIR"] = str(app_file.parent)

    print(f"[runner] Executing script mode: {app_file} (PORT={port})")
    os.execvpe(sys.executable, [sys.executable, str(app_file)], env)


def main() -> None:
    parser = argparse.ArgumentParser(description="Gateway launcher")
    parser.add_argument("--run-managed-app", nargs=2, metavar=("FILE", "PORT"))
    args = parser.parse_args()

    if args.run_managed_app:
        app_file, port_text = args.run_managed_app
        _run_managed_app(app_file, int(port_text))
        return

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)
    atexit.register(_terminate_all)

    _init_auth_storage()
    start_managed_apps()
    print(f"[gateway] UI available at http://0.0.0.0:{GATEWAY_PORT}")
    app.run(host=GATEWAY_HOST, port=GATEWAY_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
        main()