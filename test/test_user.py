#!/usr/bin/python2

from datetime import datetime
from pypassdb.user import User, ACB_NORMAL, UNKNOWN_6


def pytest_funcarg__user():
    return User()


def test_user_initialization(user):
    mintime = datetime(1970, 1, 1, 0, 0)
    maxtime = datetime(2036, 2, 6, 15, 6, 39)
    assert user.logon_time == mintime
    assert user.logoff_time == maxtime
    assert user.kickoff_time == maxtime
    assert user.bad_password_time == mintime
    assert user.pass_last_set_time == mintime
    assert user.pass_can_change_time == mintime
    assert user.pass_must_change_time == maxtime
    assert user.username == ""
    assert user.domain == ""
    assert user.nt_username == ""
    assert user.fullname == ""
    assert user.homedir == ""
    assert user.dir_drive == ""
    assert user.logon_script == ""
    assert user.profile_path == ""
    assert user.acct_desc == ""
    assert user.workstations == ""
    assert user.comment == ""
    assert user.munged_dial == ""
    assert user.user_rid == 0
    assert user.group_rid == 0
    assert user.lm_pw == ""
    assert user.nt_pw == ""
    assert user.nt_pw_hist == ""
    assert user.acct_ctrl == ACB_NORMAL
    assert user.logon_divs == 24*7
    assert user.hours_len == 21
    assert user.hours == "\xff" * user.hours_len + \
        "\x00" * (32 - user.hours_len)
    assert user.bad_password_count == 0
    assert user.logon_count == 0
    assert user.unknown_6 == UNKNOWN_6
