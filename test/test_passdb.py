#!/usr/bin/python2
from pypassdb.passdb import PassDB
from pypassdb.user import User, unpack_user, nthash
from shutil import copyfile
import tdb

DB_ORIGIN = "test/passdb.tdb"
DB_FILE = "test/passdb.tdb.test"


def test_open_close():
    copyfile(DB_ORIGIN, DB_FILE)
    pdb = PassDB(DB_FILE)
    pdb.close()


def test_append_user():
    copyfile(DB_ORIGIN, DB_FILE)
    pdb = PassDB(DB_FILE)
    pdb.append(User("foo"))
    pdb.close()
    db = tdb.open(DB_FILE)
    assert "USER_foo\x00" in db
    assert db["RID_000003e9\x00"] == "foo\x00"
    assert db["NEXT_RID\x00"] == "\xea\x03\x00\x00"
    db.close()


def test_change_password():
    copyfile(DB_ORIGIN, DB_FILE)
    pdb = PassDB(DB_FILE)
    user = pdb["naota"]
    user.set_password("hogefuga")
    pdb["naota"] = user
    pdb.close()
    db = tdb.open(DB_FILE)
    assert unpack_user(db["USER_naota\x00"]).nt_pw == \
        nthash("hogefuga").decode("hex")
    db.close()
