#!/usr/bin/env python3
#
# ----------------------------------------------------------------------------
# winsymcli - search WinAPI symbols information from cli
# ----------------------------------------------------------------------------
#
# Copyright (C) 2018 - Emanuele Faranda
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#

import os
import sys
import pickle
import argparse

from conf import *

_symbols = None

def loadSymbols():
  global _symbols

  if not _symbols:
    with open(PICKLE_DUMP_FILE, "rb") as f:
      _symbols = pickle.load(f)

  return _symbols

def getSymInfo(sym):
  syms = loadSymbols()

  if not sym in syms:
    print("[E] Symbol not found")
    return

  fn = syms[sym]

  print("%s @%s.lib %s(%s)" % (fn.get("rv", "?"), fn["lib"], sym, ", ".join(fn.get("ext_args", fn["args"]))))

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Search for symbols signatures in the database")
  parser.add_argument("sym", help="the exact symbol name to search")
  args = parser.parse_args()

  getSymInfo(args.sym)
