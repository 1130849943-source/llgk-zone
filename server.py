"""
用户系统 + 令牌访问控制
- 注册：邮箱 + 密码 + 邀请码
- 登录：邮箱 + 密码
- 仪表板：生成专属访问链接
- 访问：token绑定用户，非本人拒绝
"""
import json, time, os, sqlite3, hashlib, secrets, string
from datetime import datetime
from collections import defaultdict
from flask import Flask, request, render_template_string, redirect, make_response, g

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ============ 安全措施 ============

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Powered-By'] = ''
    response.headers['Server'] = ''
    return response

login_attempts = defaultdict(list)

def check_rate_limit(ip, action, max_attempts=5, window=300):
    now = time.time()
    attempts = [t for t in login_attempts[ip + "_" + action] if now - t < window]
    login_attempts[ip + "_" + action] = attempts
    if len(attempts) >= max_attempts:
        return False
    login_attempts[ip + "_" + action].append(now)
    return True

# 线上环境用 /data 持久化目录，本地开发用当前目录
DATA_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "app.db")
VALID_INVITE_CODES = {"INVITE2026", "VIP888", "TEST123"}
ADMIN_EMAILS = {"1130849943@qq.com"}

# ============ 数据库 ============

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            invite_code TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            daily_links INTEGER DEFAULT 0,
            last_link_date TEXT,
            is_blocked INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            expires_at TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            access_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT,
            ip TEXT,
            success INTEGER,
            reason TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    db.commit()
    db.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def gen_token():
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(16))


# ============ 页面模板 ============

# Jinja2 使用标准 {{ }} 语法，CSS/JS中的大括号用 {% raw %} 包裹

CSS = """*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f0f0f;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}.box{background:#1a1a1a;padding:40px;border-radius:12px;max-width:420px;width:90%;border:1px solid #333}h2{margin-bottom:8px;font-size:22px}.subtitle{color:#888;font-size:13px;margin-bottom:24px}input,select{width:100%;padding:12px;border-radius:8px;border:1px solid #444;background:#222;color:#fff;font-size:16px;margin-bottom:14px;outline:none}input:focus{border-color:#6366f1}button{width:100%;padding:12px;border-radius:8px;border:none;background:#6366f1;color:#fff;font-size:16px;cursor:pointer}button:hover{background:#5558e6}button:disabled{background:#444;cursor:not-allowed}button.red{background:#ef4444}button.red:hover{background:#dc2626}a{color:#6366f1;text-decoration:none;font-size:13px}.error{color:#ef4444;font-size:14px;margin-top:8px;text-align:center}.success{color:#22c55e;font-size:14px;margin-top:8px;text-align:center}.nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;font-size:13px;color:#aaa}.nav a{color:#ef4444}.table{width:100%;border-collapse:collapse;font-size:12px;margin-top:16px}.table th{text-align:left;padding:8px;color:#aaa;border-bottom:1px solid #333}.table td{padding:8px;border-bottom:1px solid #222;color:#ccc;word-break:break-all}.token{font-family:monospace;color:#22c55e;font-size:14px}label{font-size:13px;color:#aaa;display:block;margin-bottom:4px}"""

LOGIN_PAGE = (
    '<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
    '<title>登录</title><style>' + CSS + '</style></head>'
    '<body><div class="box" style="text-align:center">'
    '<h2>登录</h2><p class="subtitle">输入你的账号</p>'
    '<form method="POST" action="/login">'
    '<input type="email" name="email" placeholder="邮箱" required>'
    '<input type="password" name="password" placeholder="密码" required>'
    '<button type="submit">登录</button>'
    '</form>'
    '{% if error %}<p class="error">{{ error }}</p>{% endif %}'
    '<p style="margin-top:16px"><a href="/register">还没有账号？注册</a></p>'
    '</div></body></html>'
)

REGISTER_PAGE = (
    '<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
    '<title>注册</title><style>' + CSS + '</style></head>'
    '<body><div class="box" style="text-align:center">'
    '<h2>注册</h2><p class="subtitle">创建你的账号（需要邀请码）</p>'
    '<form method="POST" action="/register">'
    '<input type="email" name="email" placeholder="邮箱" required>'
    '<input type="password" name="password" placeholder="密码（至少6位）" required minlength="6">'
    '<input type="text" name="invite_code" placeholder="邀请码" required>'
    '<button type="submit">注册</button>'
    '</form>'
    '{% if error %}<p class="error">{{ error }}</p>{% endif %}'
    '<p style="margin-top:16px"><a href="/login">已有账号？登录</a></p>'
    '</div></body></html>'
)

DASHBOARD_CSS = CSS + (
    ".box{max-width:640px;text-align:left}"
    ".link-box{background:#111;border:1px solid #333;border-radius:8px;padding:12px;margin:8px 0;font-size:13px}"
    ".link-box .url{color:#6366f1;word-break:break-all}"
    ".link-box .meta{color:#555;font-size:11px;margin-top:4px}"
    ".gen-btn{margin:20px 0}"
    ".copy-btn{background:#333;padding:4px 10px;font-size:11px;border-radius:4px;cursor:pointer;border:none;color:#fff;margin-left:8px}"
    ".copy-btn:hover{background:#555}"
)

DASHBOARD = (
    '<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
    '<title>仪表板</title><style>' + DASHBOARD_CSS + '</style></head>'
    '<body><div class="box">'
    '<div class="nav"><span>已登录：{{ email }}{% if is_admin %} <a href="/admin" style="color:#f59e0b">管理面板</a>{% endif %}</span><a href="/logout">退出</a></div>'
    '<h2>仪表板</h2>'
    '<p style="color:#aaa;font-size:13px;margin-bottom:16px">'
    '今日已生成：{{ today_count }} 个链接 | 配额：每天最多 {{ max_daily }} 个'
    '</p>'
    '<div class="gen-btn">'
    '<form method="POST" action="/generate_link">'
    '<button type="submit" {% if quota_full %}disabled{% endif %}>'
    '{% if quota_full %}今日配额已用完{% else %}生成今日访问链接{% endif %}'
    '</button>'
    '</form>'
    '</div>'
    '{% if success %}<p class="success">{{ success }}</p>{% endif %}'
    '{% if error %}<p class="error">{{ error }}</p>{% endif %}'
    '{% if links %}'
    '<h3 style="margin-top:24px;font-size:15px;color:#aaa">已生成的链接</h3>'
    '{% for link in links %}'
    '<div class="link-box">'
    '<div><span style="color:#aaa">链接：</span><span class="url">{{ link.url }}</span>'
    '<button class="copy-btn" onclick="navigator.clipboard.writeText(\'{{ link.url }}\')">复制</button></div>'
    '<div class="meta">生成：{{ link.created_at }} | 过期：{{ link.expires_at }} | 访问：{{ link.access_count }}次 | '
    '{% if link.used %}<span style="color:#22c55e">已使用</span>{% else %}<span style="color:#f59e0b">未使用</span>{% endif %}'
    '</div>'
    '</div>'
    '{% endfor %}'
    '{% endif %}'
    '</div>'
    '<script>'
    'var cbs=document.querySelectorAll(".copy-btn");'
    'cbs.forEach(function(b){b.addEventListener("click",function(){this.textContent="已复制";setTimeout(function(){b.textContent="复制"},2000)})});'
    '</script>'
    '</body></html>'
)

ADMIN_PAGE = (
    '<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
    '<title>管理员面板</title><style>' + CSS + '.box{max-width:960px;text-align:left}.admin-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:16px}.admin-table th{text-align:left;padding:10px 8px;color:#aaa;border-bottom:2px solid #444;background:#1e1e1e;position:sticky;top:0}.admin-table td{padding:10px 8px;border-bottom:1px solid #222;color:#ccc}.admin-table tr:hover{background:#252525}.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px}.badge-blocked{background:#3b1c1c;color:#ef4444}.badge-active{background:#1c3b1c;color:#22c55e}.stats{color:#888;font-size:13px;margin-top:16px;text-align:right}</style></head>'
    '<body><div class="box">'
    '<div class="nav"><span>管理员面板</span><a href="/dashboard">返回仪表板</a></div>'
    '<h2>用户管理</h2>'
    '<p style="color:#aaa;font-size:13px;margin-bottom:16px">所有注册用户列表</p>'
    '<table class="admin-table">'
    '<thead><tr>'
    '<th>ID</th><th>邮箱</th><th>邀请码</th><th>注册时间</th><th>今日链接数</th><th>最后链接日期</th><th>状态</th>'
    '</tr></thead><tbody>'
    '{% for user in users %}'
    '<tr>'
    '<td>{{ user.id }}</td>'
    '<td>{{ user.email }}</td>'
    '<td>{{ user.invite_code }}</td>'
    '<td>{{ user.created_at }}</td>'
    '<td>{{ user.daily_links }}</td>'
    '<td>{{ user.last_link_date or "-" }}</td>'
    '<td>{% if user.is_blocked %}<span class="badge badge-blocked">已封禁</span>{% else %}<span class="badge badge-active">正常</span>{% endif %}</td>'
    '</tr>'
    '{% endfor %}'
    '</tbody></table>'
    '<div class="stats">总注册用户数：{{ total }}</div>'
    '</div></body></html>'
)

ACCESS_PAGE = (
    '<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8">'
    '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
    '<title>资源页面</title><style>' + CSS + '.box{max-width:780px;text-align:left;max-height:85vh;overflow-y:auto}.cat{color:#6366f1;font-size:16px;margin:20px 0 8px 0;border-bottom:1px solid #333;padding-bottom:4px}.table tr:nth-child(even){background:#252525}.table tr:hover{background:#2a2a2a}#searchBox:focus{border-color:#6366f1}</style></head>'
    '<body><div class="box">'
    '<h2 style="color:#22c55e;text-align:center">访问成功</h2>'
    '<p style="color:#aaa;text-align:center;margin-bottom:20px;font-size:13px">链接归属：{{ owner_email }}</p>'
    '<input type="text" id="searchBox" placeholder="搜索工具..." style="width:100%;padding:10px;border-radius:8px;border:1px solid #444;background:#222;color:#fff;font-size:14px;margin-bottom:16px;outline:none" oninput="filterTools()">'
    # ---- 在线工具箱
    '<h3 class="cat">\U0001f9f0 在线工具箱</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">IT-Tools</td><td style="padding:5px;color:#aaa">加密/转换/网络工具</td><td style="padding:5px"><a href="https://it-tools.tech" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">JustHTMLs</td><td style="padding:5px;color:#aaa">60+纯HTML工具</td><td style="padding:5px"><a href="https://justhtmls.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Mate.tools</td><td style="padding:5px;color:#aaa">文本/图像工具</td><td style="padding:5px"><a href="https://mate.tools" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">WG-Tools</td><td style="padding:5px;color:#aaa">无广告开发者工具</td><td style="padding:5px"><a href="https://wg-tools.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Toolhub</td><td style="padding:5px;color:#aaa">开发者在线工具集</td><td style="padding:5px"><a href="https://toolhub.app" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">ConvertX</td><td style="padding:5px;color:#aaa">1000+格式在线转换</td><td style="padding:5px"><a href="https://convertx.app" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 设计与图像处理
    '<h3 class="cat">\U0001f3a8 设计与图像处理</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">Krita</td><td style="padding:5px;color:#aaa">专业开源绘画</td><td style="padding:5px"><a href="https://krita.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Photopea</td><td style="padding:5px;color:#aaa">在线PS替代品</td><td style="padding:5px"><a href="https://www.photopea.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Penpot</td><td style="padding:5px;color:#aaa">开源Figma替代</td><td style="padding:5px"><a href="https://penpot.app" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Excalidraw</td><td style="padding:5px;color:#aaa">手绘风格白板</td><td style="padding:5px"><a href="https://excalidraw.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Graphite</td><td style="padding:5px;color:#aaa">矢量图形编辑器</td><td style="padding:5px"><a href="https://graphite.rs" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">unDraw</td><td style="padding:5px;color:#aaa">免费矢量插图</td><td style="padding:5px"><a href="https://undraw.co" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">PhotoDemon</td><td style="padding:5px;color:#aaa">便携图像编辑器</td><td style="padding:5px"><a href="https://photodemon.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Font Library</td><td style="padding:5px;color:#aaa">海量开源字体</td><td style="padding:5px"><a href="https://fontlibrary.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- AI漫剪与视频创作
    '<h3 class="cat">\U0001f3ac AI漫剪与视频创作</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">CapCut 剪映</td><td style="padding:5px;color:#aaa">AI自动剪辑/字幕</td><td style="padding:5px"><a href="https://www.capcut.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">RunwayML</td><td style="padding:5px;color:#aaa">AI视频编辑神器</td><td style="padding:5px"><a href="https://runwayml.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Opus Clip</td><td style="padding:5px;color:#aaa">长视频自动切短视频</td><td style="padding:5px"><a href="https://www.opus.pro" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Descript</td><td style="padding:5px;color:#aaa">AI视频/音频编辑</td><td style="padding:5px"><a href="https://www.descript.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Fliki</td><td style="padding:5px;color:#aaa">文字转视频AI</td><td style="padding:5px"><a href="https://fliki.ai" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">InVideo</td><td style="padding:5px;color:#aaa">AI视频制作平台</td><td style="padding:5px"><a href="https://invideo.io" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Pika Labs</td><td style="padding:5px;color:#aaa">AI视频生成</td><td style="padding:5px"><a href="https://pika.art" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">HeyGen</td><td style="padding:5px;color:#aaa">AI数字人视频</td><td style="padding:5px"><a href="https://www.heygen.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Clipchamp</td><td style="padding:5px;color:#aaa">微软免费剪辑</td><td style="padding:5px"><a href="https://clipchamp.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Wisecut</td><td style="padding:5px;color:#aaa">AI自动剪辑配音</td><td style="padding:5px"><a href="https://www.wisecut.video" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">VEED.io</td><td style="padding:5px;color:#aaa">在线视频编辑</td><td style="padding:5px"><a href="https://www.veed.io" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Canva</td><td style="padding:5px;color:#aaa">全能设计/视频</td><td style="padding:5px"><a href="https://www.canva.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- AI与数据科学
    '<h3 class="cat">\U0001f916 AI与数据科学</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">DeepSeek</td><td style="padding:5px;color:#aaa">国产大模型</td><td style="padding:5px"><a href="https://chat.deepseek.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Ollama</td><td style="padding:5px;color:#aaa">本地运行大模型</td><td style="padding:5px"><a href="https://ollama.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">NoteGen</td><td style="padding:5px;color:#aaa">AI笔记应用</td><td style="padding:5px"><a href="https://notegen.net" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">OpenManus</td><td style="padding:5px;color:#aaa">Manus开源替代</td><td style="padding:5px"><a href="https://github.com/mannaandpoem/OpenManus" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Qwen通义千问</td><td style="padding:5px;color:#aaa">阿里开源大模型</td><td style="padding:5px"><a href="https://tongyi.aliyun.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Mistral</td><td style="padding:5px;color:#aaa">欧洲开源大模型</td><td style="padding:5px"><a href="https://chat.mistral.ai" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- AI绘图与设计
    '<h3 class="cat">\U0001f5bc AI绘图与设计</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">Midjourney</td><td style="padding:5px;color:#aaa">AI绘画天花板</td><td style="padding:5px"><a href="https://www.midjourney.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Stable Diffusion</td><td style="padding:5px;color:#aaa">开源AI绘画</td><td style="padding:5px"><a href="https://stablediffusionweb.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">ComfyUI</td><td style="padding:5px;color:#aaa">SD节点式工作流</td><td style="padding:5px"><a href="https://github.com/comfyanonymous/ComfyUI" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Leonardo AI</td><td style="padding:5px;color:#aaa">AI绘画/游戏素材</td><td style="padding:5px"><a href="https://leonardo.ai" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Civitai</td><td style="padding:5px;color:#aaa">SD模型分享社区</td><td style="padding:5px"><a href="https://civitai.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">DALL\u00b7E 3</td><td style="padding:5px;color:#aaa">OpenAI官方绘图</td><td style="padding:5px"><a href="https://openai.com/dall-e-3" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Remove.bg</td><td style="padding:5px;color:#aaa">AI一键去背景</td><td style="padding:5px"><a href="https://www.remove.bg" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Upscayl</td><td style="padding:5px;color:#aaa">AI图片无损放大</td><td style="padding:5px"><a href="https://www.upscayl.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Vectorizer</td><td style="padding:5px;color:#aaa">位图转矢量</td><td style="padding:5px"><a href="https://vectorizer.ai" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 办公效率
    '<h3 class="cat">\U0001f4cb 办公效率</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">VS Code</td><td style="padding:5px;color:#aaa">代码编辑器</td><td style="padding:5px"><a href="https://code.visualstudio.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">LibreOffice</td><td style="padding:5px;color:#aaa">开源办公套件</td><td style="padding:5px"><a href="https://www.libreoffice.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">ONLYOFFICE</td><td style="padding:5px;color:#aaa">协作办公套件</td><td style="padding:5px"><a href="https://www.onlyoffice.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Joplin</td><td style="padding:5px;color:#aaa">加密笔记应用</td><td style="padding:5px"><a href="https://joplinapp.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">MrRSS</td><td style="padding:5px;color:#aaa">AI RSS阅读器</td><td style="padding:5px"><a href="https://github.com/nicepkg/mrrss" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 实用工具
    '<h3 class="cat">\U0001f527 实用工具</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">Blender</td><td style="padding:5px;color:#aaa">3D创作套件</td><td style="padding:5px"><a href="https://www.blender.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">OBS Studio</td><td style="padding:5px;color:#aaa">录屏/直播</td><td style="padding:5px"><a href="https://obsproject.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">VLC</td><td style="padding:5px;color:#aaa">万能视频播放器</td><td style="padding:5px"><a href="https://www.videolan.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">7-Zip</td><td style="padding:5px;color:#aaa">高压缩比解压</td><td style="padding:5px"><a href="https://7-zip.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">LocalSend</td><td style="padding:5px;color:#aaa">局域网文件传输</td><td style="padding:5px"><a href="https://localsend.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Bitwarden</td><td style="padding:5px;color:#aaa">开源密码管理器</td><td style="padding:5px"><a href="https://bitwarden.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">TestDisk</td><td style="padding:5px;color:#aaa">开源数据恢复</td><td style="padding:5px"><a href="https://www.cgsecurity.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">EasySpider</td><td style="padding:5px;color:#aaa">可视化爬虫工具</td><td style="padding:5px"><a href="https://www.easyspider.net" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">FileConverter</td><td style="padding:5px;color:#aaa">右键菜单转换器</td><td style="padding:5px"><a href="https://file-converter.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Syncthing</td><td style="padding:5px;color:#aaa">局域网文件同步</td><td style="padding:5px"><a href="https://syncthing.net" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 效率与自动化
    '<h3 class="cat">\u26a1 效率与自动化</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">uTools</td><td style="padding:5px;color:#aaa">效率神器/插件平台</td><td style="padding:5px"><a href="https://u.tools" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Everything</td><td style="padding:5px;color:#aaa">文件秒搜</td><td style="padding:5px"><a href="https://www.voidtools.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">PowerToys</td><td style="padding:5px;color:#aaa">微软官方效率套件</td><td style="padding:5px"><a href="https://learn.microsoft.com/en-us/windows/powertoys" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">AutoHotkey</td><td style="padding:5px;color:#aaa">自动化脚本</td><td style="padding:5px"><a href="https://www.autohotkey.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">QuickLook</td><td style="padding:5px;color:#aaa">空格预览文件</td><td style="padding:5px"><a href="https://github.com/QL-Win/QuickLook" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Ditto</td><td style="padding:5px;color:#aaa">剪贴板增强</td><td style="padding:5px"><a href="https://ditto-cp.sourceforge.io" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Snipaste</td><td style="padding:5px;color:#aaa">截图贴图工具</td><td style="padding:5px"><a href="https://www.snipaste.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Flow Launcher</td><td style="padding:5px;color:#aaa">快速启动器</td><td style="padding:5px"><a href="https://www.flowlauncher.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">ShareX</td><td style="padding:5px;color:#aaa">截图/录屏/上传</td><td style="padding:5px"><a href="https://getsharex.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Geek Uninstaller</td><td style="padding:5px;color:#aaa">强力卸载</td><td style="padding:5px"><a href="https://geekuninstaller.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 开发运维
    '<h3 class="cat">\U0001f4bb 开发运维</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">DBeaver</td><td style="padding:5px;color:#aaa">数据库管理客户端</td><td style="padding:5px"><a href="https://dbeaver.io" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Portainer</td><td style="padding:5px;color:#aaa">Docker可视化管理</td><td style="padding:5px"><a href="https://www.portainer.io" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">n8n</td><td style="padding:5px;color:#aaa">工作流自动化</td><td style="padding:5px"><a href="https://n8n.io" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Webmin</td><td style="padding:5px;color:#aaa">Linux服务器管理</td><td style="padding:5px"><a href="https://webmin.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">RustDesk</td><td style="padding:5px;color:#aaa">开源远程桌面</td><td style="padding:5px"><a href="https://rustdesk.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">WindTerm</td><td style="padding:5px;color:#aaa">跨平台终端工具</td><td style="padding:5px"><a href="https://github.com/kingToolbox/WindTerm" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 休闲游戏
    '<h3 class="cat">\U0001f3ae 休闲游戏</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">Wesnoth</td><td style="padding:5px;color:#aaa">回合制奇幻战棋</td><td style="padding:5px"><a href="https://www.wesnoth.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">OpenRA</td><td style="padding:5px;color:#aaa">红警开源重制</td><td style="padding:5px"><a href="https://www.openra.net" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Freeciv</td><td style="padding:5px;color:#aaa">文明风格策略</td><td style="padding:5px"><a href="https://www.freeciv.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Andor\u0027s Trail</td><td style="padding:5px;color:#aaa">开放世界RPG</td><td style="padding:5px"><a href="https://andorstrail.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Minute Maze</td><td style="padding:5px;color:#aaa">迷宫解谜游戏</td><td style="padding:5px"><a href="https://github.com/niclas-thor/minutemaze" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 资源与下载
    '<h3 class="cat">\U0001f4e6 资源与下载</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">Ninite</td><td style="padding:5px;color:#aaa">装机一条龙</td><td style="padding:5px"><a href="https://ninite.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">MassGrave</td><td style="padding:5px;color:#aaa">Windows/Office激活</td><td style="padding:5px"><a href="https://massgrave.dev" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">FileCR</td><td style="padding:5px;color:#aaa">软件资源站</td><td style="padding:5px"><a href="https://filecr.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">PDF24</td><td style="padding:5px;color:#aaa">免费PDF工具</td><td style="padding:5px"><a href="https://tools.pdf24.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">BrowserBench</td><td style="padding:5px;color:#aaa">浏览器跑分</td><td style="padding:5px"><a href="https://browserbench.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">VirusTotal</td><td style="padding:5px;color:#aaa">在线病毒扫描</td><td style="padding:5px"><a href="https://www.virustotal.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">AlternativeTo</td><td style="padding:5px;color:#aaa">软件替代品搜索</td><td style="padding:5px"><a href="https://alternativeto.net" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">RG Mechanics</td><td style="padding:5px;color:#aaa">高压游戏资源</td><td style="padding:5px"><a href="https://rg-mechanics.org" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 免费音乐下载
    '<h3 class="cat">\U0001f3b5 免费音乐下载</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">MyFreeMP3</td><td style="padding:5px;color:#aaa">免费音乐下载</td><td style="padding:5px"><a href="https://tools.liumingye.cn/music" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">MusicFree</td><td style="padding:5px;color:#aaa">开源音乐播放器</td><td style="padding:5px"><a href="https://github.com/maotoumao/MusicFree" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Listen1</td><td style="padding:5px;color:#aaa">全网音乐聚合</td><td style="padding:5px"><a href="https://listen1.github.io/listen1" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">LX Music 洛雪音乐</td><td style="padding:5px;color:#aaa">开源全网音乐</td><td style="padding:5px"><a href="https://github.com/lyswhut/lx-music-desktop" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">YesPlayMusic</td><td style="padding:5px;color:#aaa">高颜值网易云客户端</td><td style="padding:5px"><a href="https://github.com/qier222/YesPlayMusic" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Spotube</td><td style="padding:5px;color:#aaa">开源Spotify客户端</td><td style="padding:5px"><a href="https://github.com/KRTirtho/spotube" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Free MP3 Download</td><td style="padding:5px;color:#aaa">免费MP3搜索下载</td><td style="padding:5px"><a href="https://free-mp3-download.net" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Slider.kz</td><td style="padding:5px;color:#aaa">全球音乐搜索</td><td style="padding:5px"><a href="https://slider.kz" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- 钓鱼地图与户外
    '<h3 class="cat">\U0001f3a3 钓鱼地图与户外</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">\u9493\u9c7c\u4e4b\u5bb6</td><td style="padding:5px;color:#aaa">钓点/天气/潮汐</td><td style="padding:5px"><a href="https://www.diaoyu.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Fishbrain</td><td style="padding:5px;color:#aaa">全球钓点地图</td><td style="padding:5px"><a href="https://fishbrain.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">\u5965\u7ef4\u4e92\u52a8\u5730\u56fe</td><td style="padding:5px;color:#aaa">户外GPS轨迹</td><td style="padding:5px"><a href="https://www.ovital.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Windy</td><td style="padding:5px;color:#aaa">风力/天气可视化</td><td style="padding:5px"><a href="https://www.windy.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">\u4e24\u6b65\u8def</td><td style="padding:5px;color:#aaa">户外轨迹/约伴</td><td style="padding:5px"><a href="https://www.2bulu.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">\u516d\u53ea\u811a</td><td style="padding:5px;color:#aaa">户外GPS轨迹</td><td style="padding:5px"><a href="https://www.foooooot.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">\u6f6e\u6c50\u8868</td><td style="padding:5px;color:#aaa">全球潮汐预报</td><td style="padding:5px"><a href="https://www.tide-forecast.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Navionics</td><td style="padding:5px;color:#aaa">航海/水深地图</td><td style="padding:5px"><a href="https://www.navionics.com" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    # ---- Android应用
    '<h3 class="cat">\U0001f4f1 Android应用</h3>'
    '<table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px">'
    '<tr style="border-bottom:1px solid #333"><th style="text-align:left;padding:5px;color:#aaa">名称</th><th style="text-align:left;padding:5px;color:#aaa">用途</th><th style="text-align:left;padding:5px;color:#aaa">链接</th></tr>'
    '<tr><td style="padding:5px">Legado阅读</td><td style="padding:5px;color:#aaa">开源小说阅读器</td><td style="padding:5px"><a href="https://github.com/gedoor/legado" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Fossify Notes</td><td style="padding:5px;color:#aaa">开源便签</td><td style="padding:5px"><a href="https://github.com/FossifyOrg/Notes" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">CIMOC</td><td style="padding:5px;color:#aaa">多源漫画阅读器</td><td style="padding:5px"><a href="https://github.com/Haleydu/Cimoc" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Organic Maps</td><td style="padding:5px;color:#aaa">隐私离线地图</td><td style="padding:5px"><a href="https://organicmaps.app" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '<tr><td style="padding:5px">Kotatsu</td><td style="padding:5px;color:#aaa">开源漫画阅读器</td><td style="padding:5px"><a href="https://github.com/nv95/Kotatsu" target="_blank" style="color:#6366f1">打开</a></td></tr>'
    '</table>'
    '<p style="color:#555;font-size:11px;text-align:center;margin-top:16px">归属: fengchunchun | 联系邮箱: 1130849943@qq.com</p>'
    '<script>function filterTools(){var q=document.getElementById("searchBox").value.toLowerCase();var cats=document.querySelectorAll(".cat");var tables=document.querySelectorAll("table");var anyVisible=false;tables.forEach(function(t,i){var rows=t.querySelectorAll("tr:not(:first-child)");var catVisible=false;rows.forEach(function(r){var txt=r.textContent.toLowerCase();if(q===""||txt.indexOf(q)>-1){r.style.display="";catVisible=true}else{r.style.display="none"}});if(catVisible||q===""){if(cats[i])cats[i].style.display="";t.style.display="";anyVisible=true}else{if(cats[i])cats[i].style.display="none";t.style.display="none"}})}</script>'
    '</div></body></html>'
)
# ============ 路由 ============

@app.route("/")
def index():
    user_email = request.cookies.get("user_email")
    user_id = request.cookies.get("user_id")
    if user_email and user_id:
        return redirect("/dashboard")
    return render_template_string(LOGIN_PAGE)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_PAGE)
    if not check_rate_limit(request.remote_addr, "login"):
        return render_template_string(LOGIN_PAGE, error="操作太频繁，请稍后再试")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if "@" not in email or "." not in email:
        return render_template_string(LOGIN_PAGE, error="邮箱格式不正确")
    if len(password) < 6 or len(password) > 128:
        return render_template_string(LOGIN_PAGE, error="密码长度需在6-128位之间")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or user["password_hash"] != hash_password(password):
        return render_template_string(LOGIN_PAGE, error="邮箱或密码错误")
    if user["is_blocked"]:
        return render_template_string(LOGIN_PAGE, error="账号已被封禁")
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("user_email", email, max_age=86400*7, httponly=True)
    resp.set_cookie("user_id", str(user["id"]), max_age=86400*7, httponly=True)
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template_string(REGISTER_PAGE)
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    invite = request.form.get("invite_code", "").strip().upper()
    if not check_rate_limit(request.remote_addr, "register"):
        return render_template_string(REGISTER_PAGE, error="操作太频繁，请稍后再试")
    if "@" not in email or "." not in email:
        return render_template_string(REGISTER_PAGE, error="邮箱格式不正确")
    if len(password) < 6 or len(password) > 128:
        return render_template_string(REGISTER_PAGE, error="密码长度需在6-128位之间")
    if invite not in VALID_INVITE_CODES:
        return render_template_string(REGISTER_PAGE, error="邀请码无效")
    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        return render_template_string(REGISTER_PAGE, error="该邮箱已注册")
    db.execute("INSERT INTO users (email, password_hash, invite_code) VALUES (?,?,?)",
               (email, hash_password(password), invite))
    db.commit()
    user = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    resp = make_response(redirect("/dashboard"))
    resp.set_cookie("user_email", email, max_age=86400*7, httponly=True)
    resp.set_cookie("user_id", str(user["id"]), max_age=86400*7, httponly=True)
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("user_email")
    resp.delete_cookie("user_id")
    return resp


@app.route("/dashboard")
def dashboard():
    user_id = request.cookies.get("user_id")
    user_email = request.cookies.get("user_email")
    if not user_id or not user_email:
        return redirect("/login")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return redirect("/login")

    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    max_daily = 5

    if user["last_link_date"] != today_str:
        db.execute("UPDATE users SET daily_links=0, last_link_date=? WHERE id=?", (today_str, user_id))
        db.commit()
        user_daily = 0
    else:
        user_daily = user["daily_links"]

    links = db.execute(
        "SELECT * FROM links WHERE user_id=? ORDER BY id DESC LIMIT 20",
        (user_id,)
    ).fetchall()

    links_data = []
    host = request.host
    for link in links:
        url = f"http://{host}/a/{link['token']}"
        links_data.append({
            "url": url,
            "token": link["token"],
            "created_at": link["created_at"],
            "expires_at": link["expires_at"],
            "used": link["used"],
            "access_count": link["access_count"],
        })

    is_admin = (user_email in ADMIN_EMAILS)
    return render_template_string(
        DASHBOARD,
        email=user_email,
        today_count=user_daily,
        max_daily=max_daily,
        quota_full=(user_daily >= max_daily),
        links=links_data,
        is_admin=is_admin,
    )


@app.route("/generate_link", methods=["POST"])
def generate_link():
    user_id = request.cookies.get("user_id")
    if not user_id:
        return redirect("/login")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")
    max_daily = 5

    if user["last_link_date"] != today_str:
        db.execute("UPDATE users SET daily_links=0, last_link_date=? WHERE id=?", (today_str, user_id))
        db.commit()
        user_daily = 0
    else:
        user_daily = user["daily_links"]

    if user_daily >= max_daily:
        return redirect("/dashboard")

    token = gen_token()
    expires = now.replace(hour=23, minute=59, second=59).strftime("%Y-%m-%d %H:%M:%S")

    db.execute(
        "INSERT INTO links (user_id, token, expires_at) VALUES (?,?,?)",
        (user_id, token, expires)
    )
    db.execute("UPDATE users SET daily_links=daily_links+1 WHERE id=?", (user_id,))
    db.commit()

    return redirect("/dashboard")


@app.route("/a/<token>")
def access_link(token):
    db = get_db()
    link = db.execute("SELECT * FROM links WHERE token=?", (token,)).fetchone()

    if not link:
        return "<h1 style='color:#ef4444;text-align:center;margin-top:100px'>链接不存在</h1>"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if now_str > link["expires_at"]:
        db.execute("INSERT INTO access_log (user_id, token, ip, success, reason) VALUES (?,?,?,?,?)",
                   (link["user_id"], token, request.remote_addr, 0, "expired"))
        db.commit()
        return "<h1 style='color:#f59e0b;text-align:center;margin-top:100px'>链接已过期</h1>"

    visitor_id = request.cookies.get("user_id")
    owner_user = db.execute("SELECT email FROM users WHERE id=?", (link["user_id"],)).fetchone()

    if str(visitor_id) != str(link["user_id"]):
        db.execute("INSERT INTO access_log (user_id, token, ip, success, reason) VALUES (?,?,?,?,?)",
                   (link["user_id"], token, request.remote_addr, 0, "not_owner"))
        db.execute("UPDATE links SET access_count=access_count+1 WHERE id=?", (link["id"],))
        db.commit()
        return "<h1 style='color:#ef4444;text-align:center;margin-top:100px'>此链接仅限生成者本人访问<br><span style='color:#aaa;font-size:14px'>非本人访问已被记录</span><br><br><span style='color:#aaa;font-size:12px'>归属: fengchunchun | 联系邮箱: 1130849943@qq.com</span></h1>"

    db.execute("UPDATE links SET used=1, access_count=access_count+1 WHERE id=?", (link["id"],))
    db.execute("INSERT INTO access_log (user_id, token, ip, success, reason) VALUES (?,?,?,?,?)",
               (link["user_id"], token, request.remote_addr, 1, "ok"))
    db.commit()

    return render_template_string(ACCESS_PAGE, owner_email=owner_user["email"])


@app.route("/admin")
def admin_panel():
    user_id = request.cookies.get("user_id")
    user_email = request.cookies.get("user_email")
    if not user_id or not user_email:
        return redirect("/login")
    if user_email not in ADMIN_EMAILS:
        return "<h1 style='color:#ef4444;text-align:center;margin-top:100px'>无权访问</h1>"
    db = get_db()
    users = db.execute("SELECT id, email, invite_code, created_at, daily_links, last_link_date, is_blocked FROM users ORDER BY id DESC").fetchall()
    users_data = [dict(u) for u in users]
    return render_template_string(ADMIN_PAGE, email=user_email, users=users_data, total=len(users_data))


# ============ 启动 ============

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    print(f"服务器启动：http://{host}:{port}")
    print(f"邀请码：{VALID_INVITE_CODES}")
    app.run(host=host, port=port, debug=False)
