#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# NoSQLMap Copyright 2012-2017 NoSQLMap Development team
# See the file 'doc/COPYING' for copying permission

from exception import NoSQLMapException
import sys
import nsmcouch
import nsmmongo
import nsmscan
import nsmweb
import os
import signal
import ast
import argparse


def main(args):
    signal.signal(signal.SIGINT, signal_handler)
    global optionSet
    # Set a list so we can track whether options are set or not to avoid resetting them in subsequent calls to the options menu.
    optionSet = [False] * 9
    global yes_tag
    global no_tag
    yes_tag = ['y', 'Y']
    no_tag = ['n', 'N']
    global victim
    global webPort
    global uri
    global httpMethod
    global platform
    global https
    global myIP
    global myPort
    global verb
    global scanNeedCreds
    global dbPort
    # Use MongoDB as the default, since it's the least secure ( :-p at you 10Gen )
    platform = "MongoDB"
    dbPort = 27017
    myIP = "Not Set"
    myPort = "Not Set"
    if args.attack:
        attack(args)
    else:
        mainMenu()


def mainMenu():
    global platform
    global victim
    global dbPort
    global myIP
    global webPort
    global uri
    global httpMethod
    global https
    global verb
    global requestHeaders
    global postData

    mmSelect = True
    while mmSelect:
        os.system('clear')
        print(" _  _     ___  ___  _    __  __          ")
        print(r"| \| |___/ __|/ _ \| |  |  \/  |__ _ _ __ ")
        print(r"| .` / _ \__ \ (_) | |__| |\/| / _` | '_ \\")
        print(r"|_|\_\___/___/\__\_\____|_|  |_\__,_| .__/")
        print(" v0.7 codingo@protonmail.com         |_|   ")
        print("\n")
        print("1-Set options")
        print("2-NoSQL DB Access Attacks")
        print("3-NoSQL Web App attacks")
        print(f"4-Scan for Anonymous {platform} Access")
        print(f"5-Change Platform (Current: {platform})")
        print("x-Exit")

        select = input("Select an option: ")

        if select == "1":
            options()
        elif select == "2":
            if optionSet[0] and optionSet[4]:
                if platform == "MongoDB":
                    nsmmongo.netAttacks(victim, dbPort, myIP, myPort)
                elif platform == "CouchDB":
                    nsmcouch.netAttacks(victim, dbPort, myIP)
            else:
                input("Target not set! Check options.  Press enter to continue...")
        elif select == "3":
            if optionSet[0] and optionSet[2]:
                if httpMethod == "GET":
                    nsmweb.getApps(webPort, victim, uri, https, verb, requestHeaders)
                elif httpMethod == "POST":
                    nsmweb.postApps(victim, webPort, uri, https, verb, postData, requestHeaders)
            else:
                input("Options not set! Check host and URI path.  Press enter to continue...")
        elif select == "4":
            scanResult = nsmscan.massScan(platform)
            if scanResult is not None:
                optionSet[0] = True
                victim = scanResult[1]
        elif select == "5":
            platSel()
        elif select == "x":
            sys.exit()
        else:
            input("Invalid selection.  Press enter to continue.")


def build_request_headers(reqHeadersIn):
    requestHeaders = {}
    reqHeadersArray = reqHeadersIn.split(",")
    headerNames = reqHeadersArray[0::2]
    headerValues = reqHeadersArray[1::2]
    requestHeaders = dict(zip(headerNames, headerValues))
    return requestHeaders


def build_post_data(postDataIn):
    pdArray = postDataIn.split(",")
    paramNames = pdArray[0::2]
    paramValues = pdArray[1::2]
    postData = dict(zip(paramNames, paramValues))
    return postData


def attack(args):
    platform = args.platform
    victim = args.victim
    webPort = args.webPort
    dbPort = args.dbPort
    myIP = args.myIP
    myPort = args.myPort
    uri = args.uri
    https = args.https
    verb = args.verb
    httpMethod = args.httpMethod
    requestHeaders = build_request_headers(args.requestHeaders)
    postData = build_post_data(args.postData)

    if args.attack == 1:
        if platform == "MongoDB":
            nsmmongo.netAttacks(victim, dbPort, myIP, myPort, args)
        elif platform == "CouchDB":
            nsmcouch.netAttacks(victim, dbPort, myIP, args)
    elif args.attack == 2:
        if httpMethod == "GET":
            nsmweb.getApps(webPort, victim, uri, https, verb, requestHeaders, args)
        elif httpMethod == "POST":
            nsmweb.postApps(victim, webPort, uri, https, verb, postData, requestHeaders, args)
    elif args.attack == 3:
        scanResult = nsmscan.massScan(platform)
        if scanResult is not None:
            optionSet[0] = True
            victim = scanResult[1]


def platSel():
    global platform
    global dbPort
    select = True
    print("\n")

    while select:
        print("1-MongoDB")
        print("2-CouchDB")
        pSel = input("Select a platform: ")

        if pSel == "1":
            platform = "MongoDB"
            dbPort = 27017
            return
        elif pSel == "2":
            platform = "CouchDB"
            dbPort = 5984
            return
        else:
            input("Invalid selection.  Press enter to continue.")


def options():
    global victim, webPort, uri, https, platform, httpMethod
    global postData, myIP, myPort, verb, mmSelect, dbPort, requestHeaders
    requestHeaders = {}
    optSelect = True

    # Set default value if needed
    if not optionSet[0]:
        victim = "Not Set"
    if not optionSet[1]:
        webPort = 80
        optionSet[1] = True
    if not optionSet[2]:
        uri = "Not Set"
    if not optionSet[3]:
        httpMethod = "GET"
    if not optionSet[4]:
        myIP = "Not Set"
    if not optionSet[5]:
        myPort = "Not Set"
    if not optionSet[6]:
        verb = "OFF"
        optSelect = True
    if not optionSet[8]:
        https = "OFF"
        optSelect = True

    while optSelect:
        print("\n\n")
        print("Options")
        print(f"1-Set target host/IP (Current: {victim})")
        print(f"2-Set web app port (Current: {webPort})")
        print(f"3-Set App Path (Current: {uri})")
        print(f"4-Toggle HTTPS (Current: {https})")
        print(f"5-Set {platform} Port (Current : {dbPort})")
        print(f"6-Set HTTP Request Method (GET/POST) (Current: {httpMethod})")
        print(f"7-Set my local {platform}/Shell IP (Current: {myIP})")
        print(f"8-Set shell listener port (Current: {myPort})")
        print(f"9-Toggle Verbose Mode: (Current: {verb})")
        print("0-Load options file")
        print("a-Load options from saved Burp request")
        print("b-Save options file")
        print("h-Set headers")
        print("x-Back to main menu")

        select = input("Select an option: ")

        if select == "1":
            optionSet[0] = False
            while not optionSet[0]:
                is_dns = False
                victim = input("Enter the host IP/DNS name: ")
                octets = victim.split(".")

                if len(octets) != 4:
                    is_dns = True
                else:
                    is_valid_ip = True
                    for item in octets:
                        try:
                            if not (0 <= int(item) <= 255):
                                print("Bad octet in IP address.")
                                is_valid_ip = False
                                break
                        except ValueError:
                            is_dns = True
                            is_valid_ip = False
                            break
                    if not is_valid_ip and not is_dns:
                        continue

                print(f"\nTarget set to {victim}\n")
                optionSet[0] = True

        elif select == "2":
            webPort = input("Enter the HTTP port for web apps: ")
            print(f"\nHTTP port set to {webPort}\n")
            optionSet[1] = True
        elif select == "3":
            uri = input("Enter URI Path (Press enter for no URI): ")
            if len(uri) == 0:
                uri = "Not Set"
                print("\nURI Not Set.\n")
                optionSet[2] = False
            elif not uri.startswith("/"):
                uri = "/" + uri
                print(f"\nURI Path set to {uri}\n")
                optionSet[2] = True
        elif select == "4":
            if https == "OFF":
                print("HTTPS enabled.")
                https = "ON"
            else:
                print("HTTPS disabled.")
                https = "OFF"
            optionSet[8] = True
        elif select == "5":
            dbPort = int(input("Enter target MongoDB port: "))
            print(f"\nTarget Mongo Port set to {dbPort}\n")
            optionSet[7] = True
        elif select == "6":
            while True:
                print("1-Send request as a GET")
                print("2-Send request as a POST")
                method_choice = input("Select an option: ")
                if method_choice == "1":
                    httpMethod = "GET"
                    print("GET request set")
                    requestHeaders = {}
                    optionSet[3] = True
                    break
                elif method_choice == "2":
                    print("POST request set")
                    optionSet[3] = True
                    postDataIn = input("Enter POST data in a comma separated list (i.e. name1,value1,name2,value2)\n")
                    postData = build_post_data(postDataIn)
                    httpMethod = "POST"
                    break
                else:
                    print("Invalid selection")
        elif select == "7":
            optionSet[4] = False
            while not optionSet[4]:
                myIP = input(f"Enter the host IP for my {platform}/Shells: ")
                octets = myIP.split(".")
                if len(octets) != 4:
                    print("Invalid IP length.")
                    continue
                
                goodDigits = True
                for item in octets:
                    try:
                        if not (0 <= int(item) <= 255):
                            print("Bad octet in IP address.")
                            goodDigits = False
                            break
                    except ValueError:
                        print("Invalid character in IP address.")
                        goodDigits = False
                        break

                if goodDigits:
                    print(f"\nShell/DB listener set to {myIP}\n")
                    optionSet[4] = True
        elif select == "8":
            myPort = input("Enter TCP listener for shells: ")
            print(f"Shell TCP listener set to {myPort}\n")
            optionSet[5] = True
        elif select == "9":
            if verb == "OFF":
                print("Verbose output enabled.")
                verb = "ON"
            else:
                print("Verbose output disabled.")
                verb = "OFF"
            optionSet[6] = True
        elif select == "0":
            loadPath = input("Enter file name to load: ")
            csvOpt = []
            try:
                with open(loadPath, "r") as fo:
                    for line in fo:
                        csvOpt.append(line.rstrip())
            except (IOError, OSError) as e:
                print(f"I/O error({e.errno}): {e.strerror}")
                input("error reading file.  Press enter to continue...")
                return

            optList = csvOpt[0].split(",")
            victim, webPort, uri, httpMethod, myIP, myPort, verb, https = optList
            headersPos = 1
            if httpMethod == "POST":
                postData = ast.literal_eval(csvOpt[1])
                headersPos = 2
            requestHeaders = ast.literal_eval(csvOpt[headersPos])

            for i, item in enumerate(optList):
                if item != "Not Set":
                    optionSet[i] = True
        elif select == "a":
            loadPath = input("Enter path to Burp request file: ")
            reqData = []
            try:
                with open(loadPath, "r") as fo:
                    for line in fo:
                        reqData.append(line.rstrip())
            except (IOError, OSError) as e:
                print(f"I/O error({e.errno}): {e.strerror}")
                input("error reading file.  Press enter to continue...")
                return

            methodPath = reqData[0].split(" ")
            if methodPath[0] in ["GET", "POST"]:
                httpMethod = methodPath[0]
                if httpMethod == "POST":
                    post_body = reqData[-1]
                    paramsNvalues = post_body.split("&")
                    paramNames = [item.split("=")[0] for item in paramsNvalues]
                    paramValues = [item.split("=")[1] for item in paramsNvalues]
                    postData = dict(zip(paramNames, paramValues))
            else:
                print("unsupported method in request header.")
            
            # load the HTTP headers
            for line in reqData[1:]:
                if not line.strip():
                    break
                header = line.split(": ", 1)
                requestHeaders[header[0]] = header[1].strip()

            victim = requestHeaders.get("Host", "").split(":")[0]
            optionSet[0] = True
            uri = methodPath[1]
            optionSet[2] = True
        elif select == "b":
            savePath = input("Enter file name to save: ")
            try:
                with open(savePath, "w") as fo:
                    fo.write(f"{victim},{webPort},{uri},{httpMethod},{myIP},{myPort},{verb},{https}")
                    if httpMethod == "POST":
                        fo.write(f",\n{postData}")
                    fo.write(f",\n{requestHeaders}")
                    print("Options file saved!")
            except (IOError, OSError):
                print("Couldn't save options file.")
        elif select == "h":
            reqHeadersIn = input("Enter HTTP Request Header data in a comma separated list (i.e. header1,value1,header2,value2)\n")
            requestHeaders = build_request_headers(reqHeadersIn)
        elif select == "x":
            return


def build_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attack", help="1 = DB Access, 2 = Web App, 3 = Scan", type=int, choices=[1, 2, 3])
    parser.add_argument("--platform", help="Platform to attack", choices=["MongoDB", "CouchDB"], default="MongoDB")
    parser.add_argument("--victim", help="Set target host/IP (ex: localhost or 127.0.0.1)")
    parser.add_argument("--dbPort", help="Set shell listener port", type=int)
    parser.add_argument("--myIP", help="Set my local platform/Shell IP")
    parser.add_argument("--myPort", help="Set my local platform/Shell port", type=int)
    parser.add_argument("--webPort", help="Set web app port ([1 - 65535])", type=int)
    parser.add_argument("--uri", help="Set App Path. Example: '/a-path/'")
    parser.add_argument("--httpMethod", help="Set HTTP Request Method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--https", help="Toggle HTTPS", choices=["ON", "OFF"], default="OFF")
    parser.add_argument("--verb", help="Toggle Verbose Mode", choices=["ON", "OFF"], default="OFF")
    parser.add_argument("--postData", help="POST data as a comma-separated list (name1,value1,name2,value2)", default="")
    parser.add_argument("--requestHeaders", help="Request headers as a comma-separated list (name1,value1,name2,value2)", default="")

    modules = [nsmcouch, nsmmongo, nsmscan, nsmweb]
    for module in modules:
        group = parser.add_argument_group(module.__name__)
        # Assuming module.args() is defined in the imported modules
        if hasattr(module, 'args'):
            for arg in module.args():
                group.add_argument(arg[0], help=arg[1])

    return parser


def signal_handler(signal, frame):
    print("\n")
    print("CTRL+C detected.  Exiting.")
    sys.exit(0)


if __name__ == '__main__':
    # These imported modules are not standard and are part of the NoSQLMap tool.
    # The script will fail here if they are not present in the same directory.
    # This correction assumes they exist and are syntactically correct.
    parser = build_parser()
    args = parser.parse_args()
    main(args)
