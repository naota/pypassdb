# -*- coding: utf-8 -*-
import tdb
from pypassdb.user import unpack_user
from struct import unpack, pack

USER_PREFIX = "USER_"
NEXT_RID_KEY = "NEXT_RID\x00"


def userkey(user):
    return USER_PREFIX+user+"\x00"


class PassDB:
    def __init__(self, name, hash_size=0):
        self.db = tdb.open(name, hash_size)

    def __getitem__(self, name):
        return unpack_user(self.db[userkey(name)])

    def __setitem__(self, name, user):
        self.db[userkey(name)] = user.pack()

    def append(self, user):
        self.db.transaction_start()
        if user.user_rid is None:
            (rid,) = unpack("<I", self.db[NEXT_RID_KEY])
            user.user_rid = rid
            self.db[NEXT_RID_KEY] = pack("<I", rid+1)
        self.db[userkey(user.username)] = user.pack()
        self.db["RID_%08x\x00" % user.user_rid] = user.username+"\x00"
        self.db.transaction_commit()

    def close(self):
        self.db.close()
