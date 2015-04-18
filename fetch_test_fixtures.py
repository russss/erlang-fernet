# coding=utf-8
# Fetch test examples from the Fernet GitHub repository and transform them into Erlang binary format.
# (pip install dateutil erlport requests; python ./fetch_test_fixtures.py > ./test_fixtures)
from __future__ import division, absolute_import, print_function, unicode_literals
from datetime import datetime
from pytz import UTC
import requests
from dateutil import parser
from erlport import encode

SRC = "https://raw.githubusercontent.com/fernet/spec/master"

generate = requests.get("%s/generate.json" % SRC).json()
verify = requests.get("%s/verify.json" % SRC).json()
invalid = requests.get("%s/invalid.json" % SRC).json()


def unix_timestamp(datestring):
    date = parser.parse(datestring)
    epoch = datetime.fromtimestamp(0, tz=UTC)
    return int((date - epoch).total_seconds())


def convert(test):
    test["now"] = unix_timestamp(test["now"])
    return test


result = {"generate": map(convert, generate),
          "verify": map(convert, verify),
          "invalid": map(convert, invalid)}

print(encode(result))
