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
import re
import glob
import copy
import pickle
import argparse

from conf import *

"""
### BINARY FORMAT ###
    Object: { sym_name -> Descriptor }
    Descriptor: {
      "lib": "wow32",                     # the library module where the symbol is implemented
      "args": ['long', 'long', 'long'],   # function arguments signature
      "rv": "LPVOID",                     # optional: return value
      "ext_args": ['DWORD vp',            # optional: parameters with API type and name
        'DWORD dwBytes',
        'BOOL fProtectedMode'],
    }
"""

#   @ stdcall InsertMenuA(long long long long ptr)
#   @ stdcall EnumProcesses(ptr long ptr) kernel32.K32EnumProcesses
# 11  stdcall  inet_addr(str) WS_inet_addr
r_stdcall = re.compile("^[@|0-9]+\s*stdcall\s*(-[^ ]+ )*([^(]+)\(([^)]*)\)\s*([^\s]*)\s*$")

#   /* A comment */
r_comment_multiline = re.compile("/\*.*?\*/",re.DOTALL)
r_comment_single = re.compile("//.*?\n")

def getDllDir(dllname):
  return os.path.join(WINE_DLLS_PATH, dllname)

def getDllSpecFile(dllname):
  return os.path.join(WINE_DLLS_PATH, dllname, dllname + ".spec")

# DLL indexing filter
def skipDll(d):
  exclude = ["kernelbase", "sspicli", "combase", "unicows"]
  return ("-" in d) or ("d3d" in d) or ("audio" in d) or (".exe" in d) or \
    (d.startswith("msvcr") and d != "msvcr") or (d in exclude)

def listDlls():
  return [d for d in os.listdir(WINE_DLLS_PATH) if (not skipDll(d)) and os.path.isfile(getDllSpecFile(d))]

def stripComments(s):
  s = re.sub(r_comment_multiline, "", s)
  s = re.sub(r_comment_single, "", s)
  return s

def findDeclaration(haystack, fnname, res):
  # DWORD WINAPI VMM_VxDCall( DWORD service, CONTEXT *context )
  r_fn_decl = re.compile("^([^(]+)\(([^)]*)\)\s*{")
  haystack = haystack.replace("\n", "")
  m = r_fn_decl.match(haystack)

  if m:
    left = m.group(1).split()
    args = m.group(2)

    if len(left) >= 2: #and left[-1] == fnname: NOTE: sometimes this does not correspond (see last column in spec file)
      fn_rv = left[0]
      args = args.strip()

      if (not args) or (args == "void"):
        args = {}
      else:
        args = [arg.strip() for arg in args.split(",")]

      res[fnname] = {"rv":fn_rv, "args":args}

def parseModule(libname, res={}, ext_sym_map={}):
  fname = getDllSpecFile(libname)

  print("[+] %s" % libname)

  # Parse documentation strings
  doc_strings = {}

  #   CreateProcessAsUserA          (KERNEL32.@)
  #   DeleteService [ADVAPI32.@]
  #		inet_addr		(WS2_32.11)
  r_docbegin = re.compile("^\s*\**\s*([^(\s[]+)\s*[(|[]" + libname + ".[@|0-9]+[)|\]]\s*$", re.IGNORECASE)

  for source in glob.glob(os.path.join(getDllDir(libname), "*.c")):
    with open(source, "r") as f:
      search_fn = None
      fn_found = False
      fn_lines = None

      for line in f:
        m = r_docbegin.match(line)

        if m:
          search_fn = m.group(1)
          fn_lines = ["/*"] # we are inside a comment
          fn_found = False
        elif search_fn:
          fn_lines.append(line)

          if fn_found:
            if "{" in line:
              fndecl = stripComments("\n".join(fn_lines))

              if (search_fn in fndecl) and ("{" in fndecl):
                findDeclaration(fndecl, search_fn, doc_strings)
                search_fn = None
                fn_lines = None
                fn_found = False
              else:
                fn_lines = [fndecl, ]
          else:
            pos = line.find(search_fn)

            if pos >= 0:
              fn_found = True

              if "{" in line[pos+1:]:
                fndecl = stripComments("\n".join(fn_lines))
                findDeclaration(fndecl, search_fn, doc_strings)
                search_fn = None
                fn_lines = None
                fn_found = False

  # Read all symbols
  with open(fname, "r") as f:
    for line in f:
      m = r_stdcall.match(line)

      if m:
        opts = m.group(1)
        fnname = m.group(2).strip()
        args = m.group(3).split()
        ext_ref = m.group(4).strip()
        idx = ext_ref.find(".")

        if idx != -1:
          module = ext_ref[:idx]
          sym = ext_ref[idx+1:]

          if not module in ext_sym_map:
            ext_sym_map[module] = {}

          # this is an external symbol
          ext_sym_map[module][sym] = {"name": fnname, "lib": libname}
          continue

        if fnname in res:
          print("[DUP] %s in %s (already in %s)" % (fnname, libname, res[fnname]["lib"]))

          if res[fnname].get("rv"):
            # signature information is already available, avoid overwriting
            continue

        value = {"lib":libname, "args":args}

        fn_decl = doc_strings.get(fnname)

        if fn_decl and (len(fn_decl["args"]) == len(args)):
          # augument information
          value["rv"] = fn_decl["rv"]
          value["ext_args"] = fn_decl["args"]

        res[fnname] = value

  return res

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Generate symbols database")
  parser.add_argument("name", help="lib name to dump (useful for debugging)", nargs='?')
  args = parser.parse_args()
  available_dlls = ()

  if args.name:
    available_dlls = (args.name, )
  else:
    available_dlls = listDlls()

  res = {}
  ext_sym_map = {}

  for dll in available_dlls:
    parseModule(dll, res, ext_sym_map)

  if ext_sym_map:
    print("Resolving external symbols...")

    for ext_module, syms in ext_sym_map.items():
      if ext_module in available_dlls:
        for ext, syminfo in syms.items():
          resolved = res.get(ext)

          if (not syminfo["name"] in res) and resolved:
            v = copy.copy(resolved)
            v["lib"] = syminfo["lib"]
            res[syminfo["name"]] = v

  print("Dumping %d functions..." % (len(res.keys())))

  with open(PICKLE_DUMP_FILE, 'wb') as f:
    pickle.dump(res, f)
