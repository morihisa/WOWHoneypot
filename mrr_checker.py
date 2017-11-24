#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Welcome to Omotenashi Web Honeypot(WOWHoneypot)
# author @morihi_soc
# (c) 2017 @morihi_soc

import os
import sys
import traceback
import re
from argparse import ArgumentParser
from xml.etree import ElementTree

def error(message):
    print("\n\u001b[31m[ERROR] {0}\u001b[0m".format(message))
    sys.exit(1)

def parse_mrr(mrrxml, htmldirpath):
    mrrdata = {}
    mrrid_set = set()

    try:
        tree = ElementTree.parse(mrrxml)
        root = tree.getroot()
        if not root.tag == "mrrs":
            error("mrrs root tag not include.")

        print("MRRules version: {0}".format(root.get("version")))
        mrrs = root.findall('mrr')
        if len(mrrs) == 0:
            error("There is no mrr tag.")

        for mrr in mrrs:
            mrrid = -1
            trigger_data = {}
            trigger_uri = []
            trigger_header = []
            trigger_body = []
            response_data = {}
            response_header = {}

            # meta
            enable = False
            m = mrr.find('meta')
            try:
                enable = m.find('enable').text
            except AttributeError:
                error("enable is requied.")
            if not enable == "True":
                print("[mrrid:{0}] disabled.".format(mrrid))
                continue

            try:
                if len(m.findall('mrrid')) > 1:
                    error("mrrid tag duplicated.")
                mrrid = int(m.find('mrrid').text)
            except AttributeError:
                error("mrrid is requied.")
            except ValueError:
                error("mrrid({0}) is not integer.".format(m.find('mrrid').text))

            if mrrid < 1000 or mrrid > 65535:
                error("mrrid({0}) not valid. (1000 <= mrrid <= 65535))".format(str(mrrid)))

            if mrrid in mrrid_set:
                error("mrrid({0}) duplicated.".format(str(mrrid)))
            mrrid_set.add(mrrid)
            print("[mrrid:{0}]".format(mrrid), end='')

            # trigger
            trigger1 = False
            print("trigger{", end='')
            t = mrr.find('trigger')
            method = t.find('method')
            if not method is None and not method.text is None:
                trigger1 = True
                trigger_data.update({"method": method.text})
                print("M", end='')

            uris = t.findall('uri')
            for uri in uris:
                if uri.text is None:
                    error("uri tag not allow None to set.")
                trigger1 = True
                trigger_uri.append(uri.text)
                print("U", end='')
            if trigger_uri:
                trigger_data.update({"uri": trigger_uri})

            headers = t.findall('header')
            for header in headers:
                if header.text is None:
                    error("header tag not allow None to set.")
                trigger1 = True
                trigger_header.append(header.text)
                print("H", end='')
            if trigger_header:
                trigger_data.update({"header": trigger_header})

            bodies = t.findall('body')
            for body in bodies:
                if body.text is None:
                    error("body tag not allow None to set.")
                trigger1 = True
                trigger_body.append(body.text)
                print("B", end='')

            if trigger_body:
                trigger_data.update({"body": trigger_body})

            if not trigger1:
                error("no trigger.")
            print("}, response{", end='')

            # response
            r = mrr.find('response')
            default200 = False
            try:
                s = r.find("status").text
                if s is None:
                    error("status tag not allow None to set.")
                status = int(s)
            except AttributeError:
                response_data.update({"status": "200"})
                default200 = True
            except ValueError:
                error("status({0}) is not integer.".format(r.find('status').text))
            if status <= 99 or 999 < status:
                error("status({0}) not valid.".format(r.find('status').text))
            if not default200:
                response_data.update({"status": status})
                print("S", end='')

            headers = r.findall('header')
            for header in headers:
                if header.text is None:
                    error("header tag not allow None to set.")
                name  =  header.find('name')
                if name is None or name.text is None:
                    error("name tag not allow None to set.")
                value = header.find('value')
                if value is None or value.text is None:
                    error("value tag not allow None to set.")

                response_header.update({name.text: value.text})
                print("H", end='')
            response_data.update({"header": response_header})

            if len(r.findall('body')) > 1:
                error("response body tag duplicated.")

            body = r.find('body')
            if body.text is None:
                # body data from file
                if body.get("filename") is None:
                    error("body tag not allow None to set / forget filename attribute?")
                else:
                    filename = os.path.join(htmldirpath, body.get("filename"))
                    if not os.path.exists(filename) or not os.path.isfile(filename):
                        error("{0} cannnot read.".format(filename))

                    file = open(filename, 'r')
                    response_data.update({"body": file.read().strip()})
                    file.close()

            else:
                # body data from CDATA
                response_data.update({"body": body.text})
            print("B", end='')


            print("}...OK!")
            mrrdata.update({mrrid:{"trigger": trigger_data, "response": response_data}})
        print("Total: {0}".format(len(mrrdata)))
        return mrrdata
    except Exception:
        print(traceback.format_exc())
        return None

if __name__ == '__main__':
    filename = "./art/mrrules.xml"
    usage = "\t{0} [-f|--file filepath] [-h|--help]\n\tdefault path {1}".format(__file__, filename)
    argparser = ArgumentParser(usage=usage)
    argparser.add_argument('-f', '--file', dest="filename", help="path to mrrules xml file")
    args = argparser.parse_args()
    if not args.filename is None:
        filename = args.filename
    if not os.path.exists(filename) or not os.path.isfile(filename):
        print("{} file read error.".format(filename))
        sys.exit(1)

    print("{0} parse start.".format(filename))
    result = parse_mrr(filename, os.path.split(filename)[0])
    if result:
        print("SUCCESS!")
    else:
        print("TOO BAD:(")
