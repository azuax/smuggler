#!/usr/bin/python3
# MIT License
# 
# Copyright (c) 2020 Evan Custodio
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import argparse
import sys
import os
import random
import string
import importlib
import hashlib
from datetime import datetime
from lib.colorama import Fore
from Desyncr import Desyncr
from functions import banner, CF, process_uri, print_info
import multiprocessing as mp


if __name__ == "__main__":
    global NOCOLOR
    if sys.version_info < (3, 0):
        print("Error: Smuggler requires Python 3.x")
        sys.exit(1)

    Parser = argparse.ArgumentParser()
    Parser.add_argument('-u', '--url', help="Target URL with Endpoint")
    Parser.add_argument('-v', '--vhost', default="", help="Specify a virtual host")
    Parser.add_argument('-x', '--exit_early', action='store_true',help="Exit scan on first finding")
    Parser.add_argument('-m', '--method', default="POST", help="HTTP method to use (e.g GET, POST) Default: POST")
    Parser.add_argument('-l', '--log', help="Specify a log file")
    Parser.add_argument('-q', '--quiet', action='store_true', help="Quiet mode will only log issues found")
    Parser.add_argument('-t', '--timeout', default=5.0, help="Socket timeout value Default: 5")
    Parser.add_argument('--no-color', action='store_true', help="Suppress color codes")
    Parser.add_argument('-c', '--configfile', default="default.py", help="Filepath to the configuration file of payloads")
    Args = Parser.parse_args()  # returns data from the options specified (echo)

    NOCOLOR = Args.no_color
    if os.name == 'nt':
        NOCOLOR = True

    Version = "v1.1"
    banner(Version)

    if sys.version_info < (3, 0):
        print_info("Error: Smuggler requires Python 3.x")
        sys.exit(1)

    # If the URL argument is not specified then check stdin
    if Args.url is None:
        if sys.stdin.isatty():
            print_info("Error: no direct URL or piped URL specified\n")
            Parser.print_help()
            exit(1)
        Servers = sys.stdin.read().split("\n")
    else:
        Servers = [Args.url + " " + Args.method]

    FileHandle = None
    if Args.log is not None:
        try:
            FileHandle = open(Args.log, "w")
        except:
            print_info("Error: Issue with log file destination")
            print(Parser.print_help())
            sys.exit(1)

    
    processes = []
    for server in Servers:
        # If the next on the list is blank, continue
        if server == "":
            continue
        # Tokenize
        server = server.split(" ")

        # This is for the stdin case, if no method was specified default to GET
        if len(server) == 1:
            server += [Args.method]

        # If a protocol is not specified then default to https
        if server[0].lower().strip()[0:4] != "http":
            server[0] = "https://" + server[0]

        params = process_uri(server[0])
        method = server[1].upper()
        host = params[0]
        port = params[1]
        endpoint = params[2]
        SSLFlagval = params[3]
        configfile = Args.configfile

        print_info("URL        : %s"%(Fore.CYAN + server[0]), FileHandle)
        print_info("Method     : %s"%(Fore.CYAN + method), FileHandle)
        print_info("Endpoint   : %s"%(Fore.CYAN + endpoint), FileHandle)
        print_info("Configfile : %s"%(Fore.CYAN + configfile), FileHandle)
        print_info("Timeout    : %s"%(Fore.CYAN + str(float(Args.timeout)) + Fore.MAGENTA + " seconds"), FileHandle)

        sm = Desyncr(configfile, host, port, url=server[0], method=method, endpoint=endpoint, SSLFlag=SSLFlagval, logh=FileHandle, smargs=Args)
        p = mp.Process(target=sm.run)
        p.daemon = True
        p.start()
        processes.append(p)

    for p in processes:
        p.join()


    if FileHandle is not None:
        FileHandle.close()
