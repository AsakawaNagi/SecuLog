# @Time: 2025/6/2 18:39
# @Author: AsakawaNagi
# @File: test.py
# @Software: PyCharm
import pytest
import casbin

# Initialize the enforcer
enforcer = casbin.Enforcer(r"C:\Users\18715\Desktop\awesome_SecuLog\config\model.conf", r"C:\Users\18715\Desktop\awesome_SecuLog\config\policy.csv")

@pytest.mark.parametrize("user, file, action, expected", [
    ("admin", r"C:\Users\18715\Desktop\secret\secret.txt", "read", True),  # 同意
    ("guest", r"C:\Users\18715\Desktop\secret\secret.txt", "read", False),  # 拒绝
])
def test_access(user, file, action, expected):
    result = enforcer.enforce(user, file, action)
    assert result == expected