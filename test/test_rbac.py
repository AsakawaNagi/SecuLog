# @Time: 2025/6/2 20:38
# @Author: AsakawaNagi
# @File: test_rbac.py
# @Software: PyCharm

import pytest
from unittest.mock import patch, MagicMock
from rbac_auditor import RBACAuditor

@pytest.fixture
def auditor():
    return RBACAuditor("../config/model.conf", "config/policy.csv")

@patch("win32evtlog.OpenEventLog")
@patch("win32evtlog.ReadEventLog")
@patch("win32evtlog.GetOldestEventLogRecord")
def test_start_monitoring(mock_get_oldest_event_log_record, mock_read_event_log, mock_open_event_log, auditor):
    mock_handle = MagicMock()
    mock_open_event_log.return_value = mock_handle

    mock_get_oldest_event_log_record.return_value = None

    mock_event = MagicMock()
    mock_event.EventID = 4663


    def mock_read_event_log_generator():
        yield [mock_event]
        while True:
            yield []

    # 修改 side_effect 使用生成器
    mock_read_event_log.side_effect = mock_read_event_log_generator()

    with patch.object(auditor, "process_event") as mock_process_event:
        auditor.start_monitoring()

        mock_open_event_log.assert_called_once_with(None, "Security")

        mock_get_oldest_event_log_record.assert_called_once_with(mock_handle)

        assert mock_read_event_log.call_count > 0

        mock_process_event.assert_called_with(mock_event)