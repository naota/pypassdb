# -*- coding: utf-8 -*-
import tdb
from pypassdb.user import unpack_user

USER_PREFIX = "USER_"


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
        self.db.append(userkey(user.username), user.pack())

    def close(self):
        self.db.close()
