# @Time: 2025/6/2 16:52
# @Author: AsakawaNagi
# @File: database.py
# @Software: PyCharm

import sqlite3
from datetime import datetime

DB_PATH = "security_audit.db"

# 这是在创建那个violations表来记录事件
def init_db():
    """初始化数据库"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS violations
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                      user TEXT,
                      path TEXT,
                      action TEXT,
                      role TEXT)''')
        conn.commit()
        conn.close()
        print("数据库初始化成功")
    except Exception as e:
        print(f"数据库初始化出错: {e}")

def log_violation(user, path, action, role):
    """记录违规事件"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO violations (user, path, action, role) VALUES (?, ?, ?, ?)",
                  (user, path, action, role))
        conn.commit()
        conn.close()
        print(f"记录违规: {user}({role}) 尝试 {action} {path}")
    except Exception as e:
        print(f"记录违规时出错: {e}")

# 初始化数据库
init_db()