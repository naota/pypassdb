#!/usr/bin/python2

from datetime import datetime
from pypassdb.user import User, ACB_NORMAL, UNKNOWN_6, unpack_user, nthash
import smbpasswd


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
    assert user.username is None
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


blob = '\x00\x00\x00\x00\x7f\xa9T|\x7f\xa9T|\x00\x00\x00\x00(x\xbfR\x00' \
       '\x00\x00\x00\x7f\xa9T|\x06\x00\x00\x00naota\x00\x07\x00\x00\x00' \
       'KEYAKI\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00' \
       '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00' \
       '\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00' \
       '\x00\xe8\x03\x00\x00\x01\x02\x00\x00\x00\x00\x00\x00\x10\x00\x00' \
       '\x00Rr\xf5\xe0\xe9\n\x985\x9c\x10\xb0Q\x8c\x91%\xca\x00\x00\x00' \
       '\x00\x10\x00\x00\x00\xa8\x00\x15\x00\x00\x00 \x00\x00\x00\xff' \
       '\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff' \
       '\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
       '\x00\x00\x00\xec\x04\x00\x00'


def pytest_funcarg__user_bin():
    return unpack_user(blob)


def test_user_from_binary(user_bin):
    assert user_bin.username == "naota"
    assert user_bin.user_rid == 1000
    assert user_bin.pass_last_set_time == datetime(2013, 12, 29, 1, 17, 28)
    assert user_bin.domain == "KEYAKI"
    assert user_bin.group_rid == 513
    assert user_bin.lm_pw == ""
    assert user_bin.nt_pw == nthash('hoge').decode("hex")


def test_pack_unpack_same(user_bin):
    assert user_bin.pack() == blob


def test_hash_is_same():
    assert nthash("hoge") == smbpasswd.nthash("hoge")
