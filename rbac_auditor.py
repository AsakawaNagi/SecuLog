# @Time: 2025/6/2 16:37
# @Author: AsakawaNagi
# @File: report_generator.py
# @Software: PyCharm

import casbin
import win32evtlog


class RBACAuditor:
    def __init__(self, model_path, policy_path):
        self.enforcer = casbin.Enforcer(model_path, policy_path)
        self._event_hand = None

        # 角色映射配置，第一次写查找不到是因为没有转义字符
        self.ROLE_MAP = {
            "Administrator": "admin",
            "asakawaslegionr\\18715": "guest",
            "18715": "guest",
            "Guest": "guest",
            "WDAGUtilityAccount": "blocked"
        }

        # 监控设置 - 文件相关事件。这里可以按要求再加新的事件id的
        self.MONITOR_EVENTS = [4663, 4656, 4658, 4660]

    def open_event_log(self):
        """打开事件日志连接"""
        if self._event_hand is None:
            self._event_hand = win32evtlog.OpenEventLog(None, "Security")
            win32evtlog.GetOldestEventLogRecord(self._event_hand)
            print("事件日志已打开")

    def close_event_log(self):
        """关闭事件日志连接"""
        if self._event_hand:
            win32evtlog.CloseEventLog(self._event_hand)
            self._event_hand = None
            print("事件日志已关闭")

    def check_events(self):
        """检查并处理新事件"""
        if self._event_hand is None:
            self.open_event_log()

        try:
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(self._event_hand, flags, 0)

            if events:
                print(f"发现 {len(events)} 条新事件")
                for event in events:
                    if event.EventID not in self.MONITOR_EVENTS:
                        continue  # 跳过不相关的事件
                    print(f"检测到事件 ID: {event.EventID}")
                    self.process_event(event)
            else:
                print("未发现新事件")

        except Exception as e:
            print(f"读取事件日志时出错: {e}")

    def process_event(self, event):
        """处理单个事件日志"""
        # 解析事件数据
        event_data = self.parse_event(event)

        if not all(event_data.values()):
            print("无法从事件中提取完整信息")
            return

        # 获取用户角色
        user_role = self.get_user_role(event_data["user"])

        # 检查权限
        if not self.enforcer.enforce(user_role, event_data["path"], event_data["action"]):
            # 记录违规
            from database import log_violation
            log_violation(
                user=event_data["user"],
                path=event_data["path"],
                action=event_data["action"],
                role=user_role
            )

    # 最重要的一个函数 在读取的时候从最新的事件开始读取
    def parse_event(self, event):
        """解析事件数据"""
        try:
            user = None
            path = None
            action = None

            if not event.StringInserts:
                print("事件缺少StringInserts数据")
                return {
                    "user": None,
                    "path": None,
                    "action": None
                }

            # 输出事件数据
            print(f"事件StringInserts: {event.StringInserts}")

            if len(event.StringInserts) > 1:
                user = event.StringInserts[1]

            if len(event.StringInserts) > 6:
                path = event.StringInserts[6]

            if len(event.StringInserts) > 9:
                access_mask_str = event.StringInserts[9]
                action = self.parse_access_mask(access_mask_str)

            print(f"解析到的用户: {user}")
            print(f"解析到的路径: {path}")
            print(f"解析到的操作: {action}")

            return {
                "user": user,
                "path": path,
                "action": action
            }
        except Exception as e:
            print(f"解析事件数据时出错: {e}")
            return {
                "user": None,
                "path": None,
                "action": None
            }

    def parse_access_mask(self, mask_str):
        """解析访问掩码字符串为操作类型"""
        try:
            if not mask_str or not mask_str.startswith("0x"):
                print(f"无效的访问掩码格式: {mask_str}")
                return "unknown"

            # 转换为整数
            mask = int(mask_str, 16)

            # 定义常见的文件操作权限映射
            if mask & 0x0002:  # 写
                return "write"
            elif mask & 0x0001:  # 读（另一种）
                return "read"
            elif mask & 0x0010:  # 删除
                return "delete"
            elif mask & 0x20000:  # 读
                return "read"
            elif mask & 0x40000:  # 修改
                return "write"
            else:
                print(f"未知访问掩码: 0x{mask:X}")
                return "unknown"
        except Exception as e:
            print(f"解析访问掩码时出错: {e}")
            return "unknown"

    def get_user_role(self, username):
        # 获取用户角色，如果不在MAP里的话自动为guest
        return self.ROLE_MAP.get(username, "guest")
