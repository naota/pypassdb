# -*- coding: utf-8 -*-
from datetime import datetime

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


class User:
    def __init__(self):
        mintime = datetime(1970, 1, 1, 0, 0)
        maxtime = datetime(2036, 2, 6, 15, 6, 39)
        self.logon_time = mintime
        self.logoff_time = maxtime
        self.kickoff_time = maxtime
        self.bad_password_time = mintime
        self.pass_last_set_time = mintime
        self.pass_can_change_time = mintime
        self.pass_must_change_time = maxtime
        self.username = ""
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
