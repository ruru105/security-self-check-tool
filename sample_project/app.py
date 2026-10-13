# -*- coding: utf-8 -*-
"""
デモ用のサンプルコードです。意図的によくある問題を含めています。
「▶ サンプルで試す」のときに使います。実際のサービスには使わないでください。
"""
import hashlib
import os
import sqlite3
import subprocess

# 1) 秘密情報の直書き(detect-secretsで検出)
API_KEY = "sk-live-1234567890abcdefABCDEF1234567890"
DB_PASSWORD = "P@ssw0rd123!"


def search_user(name):
    # 2) SQL文を文字列結合で組み立てている(SQLインジェクション / bandit B608)
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query).fetchall()


def run_backup(filename):
    # 3) ユーザー入力をそのままシェルコマンドに渡している(bandit B602/605)
    subprocess.call("tar -cf backup.tar " + filename, shell=True)


def hash_password(password):
    # 4) 弱いハッシュ関数をパスワードに使用(bandit B303/324)
    return hashlib.md5(password.encode()).hexdigest()


def load_config(path):
    # 5) 信頼できないデータのpickle復元(bandit B301)
    import pickle
    with open(path, "rb") as f:
        return pickle.load(f)


def debug_eval(expr):
    # 6) evalにユーザー入力を渡している(bandit B307)
    return eval(expr)
