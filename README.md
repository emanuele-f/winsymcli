# winsymcli

winsymcli is a tool to search WinAPI symbols information from cli.

Example:

```
$ ./winsymcli.py WSAStartup
int @ws2_32.lib WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
```

*Note*: the library name may be inaccurate as the symbol may be defined in multiple
libraries

## How it works

It parses the [WineAPI](https://source.winehq.org/WineAPI) library files to extract symbols
names and try to resolve functions signatures. The extracted information is then used by the
`winsymcli.py` tool.

## Creating the database

The `winapi_syms.pickle` (already distributed within this repo) can be manually generated with the
following commands:

```
git clone --depth 1 "git://source.winehq.org/git/wine.git" wine
./sym_gen.py
```

## Missing signatures

Sometimes symbols signature cannot be determined automatically. In this case, a question mark
will be the first characted of the output. Here is an example:

```
./winsymcli.py DllGetClassObject
? @dinput8.lib DllGetClassObject(ptr, ptr, ptr)
```

Please open an issue with such symbols as their detection needs to be fixed.
