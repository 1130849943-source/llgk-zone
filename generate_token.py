"""
令牌生成器
每次运行生成一个新的10位临时令牌（大小写字母+数字），有效期1天
"""
import json
import time
import secrets
import string
import os

# 生成10位随机令牌（大小写字母 + 数字）
chars = string.ascii_letters + string.digits
token_str = ''.join(secrets.choice(chars) for _ in range(10))

# 过期时间：当前时间 + 1天
expire_time = int(time.time()) + 86400

# 存入 tokens.json
tokens_file = os.path.join(os.path.dirname(__file__), "tokens.json")
tokens = {}
if os.path.exists(tokens_file):
    with open(tokens_file, "r", encoding="utf-8") as f:
        tokens = json.load(f)

tokens[token_str] = {
    "expire": expire_time,
    "created": time.strftime("%Y-%m-%d %H:%M:%S"),
}

with open(tokens_file, "w", encoding="utf-8") as f:
    json.dump(tokens, f, ensure_ascii=False, indent=2)

print("=" * 50)
print("  新令牌已生成（有效期至", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expire_time)), "）")
print("=" * 50)
print()
print("令牌：")
print(token_str)
print()
print("访问链接：")
print(f"http://你的服务器地址:5000/?token={token_str}")
print()
print("=" * 50)
print("将此10位令牌发送给需要访问的人，1天后自动失效。")
