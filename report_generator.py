import sqlite3
from datetime import datetime, timedelta

def generate_report(days=1):
    """生成审计报告"""
    try:
        conn = sqlite3.connect("security_audit.db")
        c = conn.cursor()

        # 获取最近违规
        c.execute("SELECT * FROM violations WHERE timestamp > ?",
                  (datetime.now() - timedelta(days=days),))
        violations = c.fetchall()

        print("\n" + "=" * 50)
        print(f"安全审计报告 - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("=" * 50)

        if not violations:
            print("未检测到策略违规")
        else:
            print(f"发现 {len(violations)} 次策略违规:\n")
            for i, violation in enumerate(violations, 1):
                print(f"{i}. [{violation[1]}] 用户: {violation[2]}({violation[5]})")
                print(f" 操作: {violation[4]} 路径: {violation[3]}")

        print("\n" + "=" * 50)
        print("建议: 检查策略配置或用户权限分配")

        # 关闭数据库连接
        conn.close()
    except Exception as e:
        print(f"生成审计报告时出错: {e}")