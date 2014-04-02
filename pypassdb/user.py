# -*- coding: utf-8 -*-
from datetime import datetime
import struct
import hashlib

# acct_ctrl flag
ACB_DISABLED = 0x00000001
ACB_HOMDIRREQ = 0x00000002
ACB_PWNOTREQ = 0x00000004
ACB_TEMPDUP = 0x00000008
ACB_NORMAL = 0x00000010
ACB_MNS = 0x00000020
ACB_DOMTRUST = 0x00000040
ACB_WSTRUST = 0x00000080
ACB_SVRTRUST = 0x00000100
ACB_PWNOEXP = 0x00000200
ACB_AUTOLOCK = 0x00000400
ACB_ENC_TXT_PWD_ALLOWED = 0x00000800
ACB_SMARTCARD_REQUIRED = 0x00001000
ACB_TRUSTED_FOR_DELEGATION = 0x00002000
ACB_NOT_DELEGATED = 0x00004000
ACB_USE_DES_KEY_ONLY = 0x00008000
ACB_DONT_REQUIRE_PREAUTH = 0x00010000
ACB_PW_EXPIRED = 0x00020000
ACB_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000
ACB_NO_AUTH_DATA_REQD = 0x00080000
ACB_PARTIAL_SECRETS_ACCOUNT = 0x00100000
ACB_USE_AES_KEYS = 0x00200000

# unknown_6 constant
UNKNOWN_6 = 0x000004ec


def nthash(text):
    return hashlib.new('md4', "hoge".encode('utf-16le')).hexdigest().upper()


class User:
    def __init__(self, username=None):
        mintime = datetime(1970, 1, 1, 0, 0)
        maxtime = datetime(2036, 2, 6, 15, 6, 39)
        self.logon_time = mintime
        self.logoff_time = maxtime
        self.kickoff_time = maxtime
        self.bad_password_time = mintime
        self.pass_last_set_time = mintime
        self.pass_can_change_time = mintime
        self.pass_must_change_time = maxtime
        self.username = username
        self.domain = ""
        self.nt_username = ""
        self.fullname = ""
        self.homedir = ""
        self.dir_drive = ""
        self.logon_script = ""
        self.profile_path = ""
        self.acct_desc = ""
        self.workstations = ""
        self.comment = ""
        self.munged_dial = ""
        self.user_rid = 0
        self.group_rid = 0
        self.lm_pw = ""
        self.nt_pw = ""
        self.nt_pw_hist = ""
        self.acct_ctrl = ACB_NORMAL
        self.logon_divs = 24*7
        self.hours_len = 21
        self.hours = "\xff" * self.hours_len + "\x00" * (32 - self.hours_len)
        self.bad_password_count = 0
        self.logon_count = 0
        self.unknown_6 = UNKNOWN_6

    def pack(self):
        def pack_string(data, isbyte=False):
            if not isbyte:
                data = data + "\x00"
            if data == "":
                return "\x00\x00\x00\x00"
            return struct.pack("<I%ds" % len(data), len(data), data)

        def pack_bstring(data):
            return pack_string(data, True)

        def utctimestamp(x):
            n = int((x-datetime.utcfromtimestamp(0)).total_seconds())
            assert(n >= 0)
            return n
        timev = \
            (self.logon_time, self.logoff_time, self.kickoff_time,
             self.bad_password_time, self.pass_last_set_time,
             self.pass_can_change_time, self.pass_must_change_time)
        secv = map(utctimestamp, timev)
        return struct.pack("<IIIIIII", secv[0], secv[1], secv[2], secv[3],
                           secv[4], secv[5], secv[6]) + \
            "".join(map(pack_string,
                    [self.username,
                     self.domain,
                     self.nt_username,
                     self.fullname])) + \
            "".join(map(pack_bstring,
                    [self.homedir,
                     self.dir_drive,
                     self.logon_script,
                     self.profile_path])) + \
            "".join(map(pack_string,
                    [self.acct_desc,
                     self.workstations,
                     self.comment,
                     self.munged_dial])) + \
            struct.pack("<II", self.user_rid, self.group_rid) + \
            "".join(map(pack_bstring,
                    [self.lm_pw,
                     self.nt_pw,
                     self.nt_pw_hist])) + \
            struct.pack("<IHI", self.acct_ctrl, self.logon_divs,
                        self.hours_len) + \
            pack_bstring(self.hours) + \
            struct.pack("<HHI", self.bad_password_count, self.logon_count,
                        self.unknown_6)

    def set_password(self, pwd):
        self.nt_pw = nthash(pwd).decode("hex")


def unpack_user(data):
    def unpack(fmt, data):
        n = struct.calcsize(fmt)
        x = struct.unpack(fmt, data[:n])
        return (data[n:], x)

    def unpack_string(data, isbyte=False):
        (n,) = struct.unpack("<I", data[:4])
        x = struct.unpack("%ds" % n, data[4:4+n])
        if n == 0:
            assert(isbyte)
            return (data[4:], "")
        if isbyte:
            return (data[4+n:], x[0])
        else:
            assert(x[0][-1] == "\x00")
            return (data[4+n:], x[0][:-1])

    def unpack_bstring(data):
        return unpack_string(data, True)

    # SAMU_BUFFER_FORMAT_V3       "dddddddBBBBBBBBBBBBddBBBdwdBwwd"
    user = User()
    (data, v1) = unpack("<IIIIIII", data)
    (user.logon_time, user.logoff_time, user.kickoff_time,
     user.bad_password_time, user.pass_last_set_time,
     user.pass_can_change_time, user.pass_must_change_time) = \
        map(datetime.utcfromtimestamp, v1)
    (data, user.username) = unpack_string(data)
    (data, user.domain) = unpack_string(data)
    (data, user.nt_username) = unpack_string(data)
    (data, user.fullname) = unpack_string(data)
    (data, user.homedir) = unpack_bstring(data)
    (data, user.dir_drive) = unpack_bstring(data)
    (data, user.logon_script) = unpack_bstring(data)
    (data, user.profile_path) = unpack_bstring(data)
    (data, user.acct_desc) = unpack_string(data)
    (data, user.workstations) = unpack_string(data)
    (data, user.comment) = unpack_string(data)
    (data, user.munged_dial) = unpack_string(data)
    (data, (user.user_rid, user.group_rid)) = unpack("<II", data)
    (data, user.lm_pw) = unpack_bstring(data)
    (data, user.nt_pw) = unpack_bstring(data)
    (data, user.nt_pw_hist) = unpack_bstring(data)
    (data, (user.acct_ctrl, user.logon_divs, user.hours_len)) = \
        unpack("<IHI", data)
    (data, user.hours) = unpack_bstring(data)
    (data, (user.bad_password_count, user.logon_count, user.unknown_6)) = \
        unpack("<HHI", data)
    assert(data == "")
    return user
