import time
from database import init_db
from rbac_auditor import RBACAuditor
from report_generator import generate_report


def main():
    # 初始化数据库
    print("正在初始化数据库...")
    init_db()
    print("数据库初始化完成")

    # 加载RBAC模型和策略
    model_file = 'config/model.conf'
    policy_file = 'config/policy.csv'
    print(f"正在加载RBAC模型: {model_file}")
    print(f"正在加载RBAC策略: {policy_file}")
    auditor = RBACAuditor(model_file, policy_file)

    # 启动安全事件监控
    print("启动安全事件监控...")
    print("提示: 程序将在15秒后自动退出并生成审计报告")

    # 设置持续时间。我测试15秒已经够找完我写这个当天的违规事项了
    start_time = time.time()
    duration = 15

    try:
        # 打开事件日志连接
        auditor.open_event_log()

        while time.time() - start_time < duration:
            # 检查并处理事件
            auditor.check_events()
            remaining = max(0, int(duration - (time.time() - start_time)))
            print(f"\r剩余时间: {remaining}秒", end="", flush=True)
            time.sleep(1)

    finally:
        # 关闭事件日志连接
        auditor.close_event_log()
        print("\n监控已停止")
        print("正在生成审计报告...")
        generate_report()


if __name__ == "__main__":
    main()