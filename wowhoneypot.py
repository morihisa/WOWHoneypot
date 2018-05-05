#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# Welcome to Omotenashi Web Honeypot(WOWHoneypot)
# author @morihi_soc
# (c) 2017 @morihi_soc

import os
import sys
import traceback
import threading
import re
import random
import base64
import binascii
import logging
import logging.handlers
import socket
import select
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from mrr_checker import parse_mrr
from datetime import datetime, timedelta, timezone

WOWHONEYPOT_VERSION = "1.1"

JST = timezone(timedelta(hours=+9), 'JST')
logger = logging.getLogger('SyslogLogger')
logger.setLevel(logging.INFO)
syslog_enable = False
hunt_enable = False
ip = "0.0.0.0"
port = 8000
serverheader = "test"
artpath = "./art/"
accesslogfile = ""
wowhoneypotlogfile = ""
huntrulelogfile = ""
hunt_rules = []
default_content = []
mrrdata = {}
mrrids = []
timeout = 3.0
blacklist = {}

class WOWHoneypotHTTPServer(HTTPServer):
    def server_bind(self):
        HTTPServer.server_bind(self)
        self.socket.settimeout(timeout)

    def finish_request(self, request, client_address):
        request.settimeout(timeout)
        HTTPServer.finish_request(self, request, client_address)

class WOWHoneypotRequestHandler(BaseHTTPRequestHandler):
    def send_response(self, code, message=None):
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header('Date', self.date_time_string())
        self.error_message_format = "error"
        self.error_content_type = "text/plain"

    def handle_one_request(self):
        if self.client_address[0] in blacklist and blacklist[self.client_address[0]] > 3:
            logging_system("Access from blacklist ip({0}). denied.".format(self.client_address[0]), True, False)
            self.close_connection = True
            return
        try:
            (r, w, e) = select.select([self.rfile], [], [], timeout)
            if len(r) == 0:
                errmsg = "Client({0}) data sending was too late.".format(self.client_address[0])
                raise socket.timeout(errmsg)
            else:
                self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = True
                return

            rrl = str(self.raw_requestline, 'iso-8859-1')
            rrl = rrl.rstrip('\r\n')
            if rrl.endswith("HTTP/1.0") or rrl.endswith("HTTP/1.1"):
                rrlmethod = rrl[:rrl.index(" ")]
                rrluri = rrl[rrl.index(" ")+1:rrl.rindex(" ")].replace(" ", "%20")
                rrlversion = rrl[rrl.rindex(" ")+1:]
                rrl2 = rrlmethod + " " + rrluri + " " + rrlversion
                self.raw_requestline = rrl2.encode()

            if not self.parse_request():
                errmsg = "Client({0}) data cannot parse. {1}".format(self.client_address[0], str(self.raw_requestline))
                raise ValueError(errmsg)

            body = ""
            if 'content-length' in self.headers:
                content_len = int(self.headers['content-length'])
                if content_len > 0:
                    post_body = self.rfile.read(content_len)
                    body = post_body.decode()

            match = False
            for id in mrrids:
                if match:
                    break

                if "method" in mrrdata[id]["trigger"]:
                    if not self.command == mrrdata[id]["trigger"]["method"]:
                        continue

                uricontinue = False
                if "uri" in mrrdata[id]["trigger"]:
                    for u in mrrdata[id]["trigger"]["uri"]:
                        if re.search(u, self.path) is None:
                            uricontinue = True
                if uricontinue:
                    continue

                headercontinue = False
                if "header" in mrrdata[id]["trigger"]:
                    for h in mrrdata[id]["trigger"]["header"]:
                        if re.search(h, str(self.headers)) is None:
                            headercontinue = True
                if headercontinue:
                    continue

                bodycontinue = False
                if "body" in mrrdata[id]["trigger"]:
                    if len(body) == 0:
                        continue
                    for b in mrrdata[id]["trigger"]["body"]:
                        if re.search(b, body) is None:
                            bodycontinue = True
                if bodycontinue:
                    continue
                match = id

            status = 200
            tmp = self.requestline.split()
            if len(tmp) == 3:
                self.protocol_version = "{0}".format(tmp[2].strip())
            else:
                self.protocol_version = "HTTP/1.1"

            if not match:
                self.send_response(200)
                self.send_header("Server", serverheader)
                self.send_header('Content-Type', 'text/html')
                r = default_content[random.randint(0, len(default_content)-1)]
                self.send_header('Content-Length', len(r))
                self.end_headers()
                self.wfile.write(bytes(r, "utf-8"))
            else:
                status = mrrdata[match]["response"]["status"]
                self.send_response(status)
                header_server_flag = False
                header_content_type_flag = False
                for name, value in mrrdata[match]["response"]["header"].items():
                    self.send_header(name, value)
                    if name == "Server":
                        header_server_flag = True
                    elif name == "Content-Type":
                        header_content_type_flag = True

                if not header_server_flag:
                    self.send_header('Server', serverheader)
                if not header_content_type_flag:
                    self.send_header('Content-Type', 'text/html')
                r = mrrdata[match]["response"]["body"]
                self.send_header('Content-Length', len(r))
                self.end_headers()
                self.wfile.write(bytes(r, "utf-8"))

            self.wfile.flush()

            # logging
            hostname = None
            if "host" in self.headers:

                if self.headers["host"].find(" ") == -1:
                    hostname = self.headers["host"]
                else:
                    hostname = self.headers["host"].split(" ")[0]
                if hostname.find(":") == -1:
                    hostname = hostname + ":80"
            else:
                hostname = "blank:80"

            request_all = self.requestline + "\n" + str(self.headers) + body
            logging_access("[{time}] {clientip} {hostname} \"{requestline}\" {status_code} {match_result} {requestall}\n".format(  time=get_time(),
                                                                    clientip=self.client_address[0],
                                                                    hostname=hostname,
                                                                    requestline=self.requestline,
                                                                    status_code=status,
                                                                    match_result=match,
                                                                    requestall=base64.b64encode(request_all.encode('utf-8')).decode('utf-8')
                                                                    ))
            # Hunting
            decoded_request_all = urllib.parse.unquote(request_all)
            for hunt_rule in hunt_rules:
                for hit in re.findall(hunt_rule, decoded_request_all):
                    logging_hunt("[{time}] {clientip} {hit}\n".format(    time=get_time(),
                                                                        clientip=self.client_address[0],
                                                                        hit=hit))

        except socket.timeout as e:
            emsg = "{0}".format(e)
            if emsg == "timed out":
                errmsg = "Session timed out. Client IP: {0}".format(self.client_address[0])
            else:
                errmsg = "Request timed out: {0}".format(emsg)
            self.log_error(errmsg)
            self.close_connection = True
            logging_system(errmsg, True, False)
            if self.client_address[0] in blacklist:
                blacklist[self.client_address[0]] = blacklist[self.client_address[0]] + 1
            else:
                blacklist[self.client_address[0]] = 1
            return
        except Exception as e:
            errmsg = "Request handling Failed: {0} - {1}".format(type(e), e)
            self.close_connection = True
            logging_system(errmsg, True, False)
            if self.client_address[0] in blacklist:
                blacklist[self.client_address[0]] = blacklist[self.client_address[0]] + 1
            else:
                blacklist[self.client_address[0]] = 1
            return

def logging_access(log):
    with open(accesslogfile, 'a') as f:
        f.write(log)
    if syslog_enable:
        logger.log(msg="{0} {1}".format(__file__, log), level=logging.INFO)

def logging_system(message, is_error, is_exit):
    if not is_error: #CYAN
        print("\u001b[36m[INFO]{0}\u001b[0m".format(message))
        file = open(wowhoneypotlogfile, "a")
        file.write("[{0}][INFO]{1}\n".format(get_time(), message))
        file.close()

    else: #RED
        print("\u001b[31m[ERROR]{0}\u001b[0m".format(message))
        file = open(wowhoneypotlogfile, "a")
        file.write("[{0}][ERROR]{1}\n".format(get_time(), message))
        file.close()

    if is_exit:
        sys.exit(1)

# Hunt
def logging_hunt(message):
    with open(huntrulelogfile, 'a') as f:
        f.write(message)

def get_time():
    return "{0:%Y-%m-%d %H:%M:%S%z}".format(datetime.now(JST))

def config_load():
    configfile = "./config.txt"
    if not os.path.exists(configfile):
        print("\u001b[31m[ERROR]{0} dose not exist...\u001b[0m".format(configfile))
        sys.exit(1)
    with open(configfile, 'r') as f:
        logpath = "./"
        accesslogfile_name = "access_log"
        wowhoneypotlogfile_name = "wowhoneypot.log"
        huntlog_name = "hunting.log"
        syslogport = 514

        for line in f:
            if line.startswith("#") or line.find("=") == -1:
                continue
            if line.startswith("serverheader"):
                global serverheader
                serverheader = line.split('=')[1].strip()
            if line.startswith("port"):
                global port
                port = int(line.split('=')[1].strip())
            if line.startswith("artpath"):
                artpath = line.split('=')[1].strip()
            if line.startswith("logpath"):
                logpath = line.split('=')[1].strip()
            if line.startswith("accesslog"):
                accesslogfile_name = line.split('=')[1].strip()
            if line.startswith("wowhoneypotlog"):
                wowhoneypotlogfile_name = line.split('=')[1].strip()
            if line.startswith("syslog_enable"):
                global syslog_enable
                if line.split('=')[1].strip() == "True":
                    syslog_enable = True
                else:
                    syslog_enable = False
            if line.startswith("syslogserver"):
                syslogserver = line.split('=')[1].strip()
            if line.startswith("syslogport"):
                syslogport = line.split('=')[1].strip()
            if line.startswith("hunt_enable"):
                global hunt_enable
                if line.split('=')[1].strip() == "True":
                    hunt_enable = True
                else:
                    hunt_enable = False
            if line.startswith("huntlog"):
                huntlog_name = line.split('=')[1].strip()

        global accesslogfile
        accesslogfile = os.path.join(logpath, accesslogfile_name)

        global wowhoneypotlogfile
        wowhoneypotlogfile = os.path.join(logpath, wowhoneypotlogfile_name)

        global huntrulelogfile
        huntrulelogfile = os.path.join(logpath, huntlog_name)

    # art directory Load
    if not os.path.exists(artpath) or not os.path.isdir(artpath):
        logging_system("{0} directory load error.".format(arttpath), True, True)

    defaultfile = os.path.join(artpath, "mrrules.xml")
    if not os.path.exists(defaultfile) or not os.path.isfile(defaultfile):
        logging_system("{0} file load error.".format(defaultfile), True, True)

    logging_system("mrrules.xml reading start.", False, False)

    global mrrdata
    mrrdata = parse_mrr(defaultfile, os.path.split(defaultfile)[0])

    global mrrids
    mrrids = sorted(list(mrrdata.keys()), reverse=True)

    if mrrdata:
        logging_system("mrrules.xml reading complete.", False, False)
    else:
        logging_system("mrrules.xml reading error.", True, True)


    defaultlocal_file = os.path.join(artpath, "mrrules_local.xml")
    if os.path.exists(defaultlocal_file) and os.path.isfile(defaultlocal_file):
        logging_system("mrrules_local.xml reading start.", False, False)
        mrrdata2 = parse_mrr(defaultlocal_file, os.path.split(defaultfile)[0])

        if mrrdata2:
            logging_system("mrrules_local.xml reading complete.", False, False)
        else:
            logging_system("mrrules_local.xml reading error.", True, True)

        mrrdata.update(mrrdata2)
        mrrids = sorted(list(mrrdata.keys()), reverse=True)

    artdefaultpath = os.path.join(artpath, "default")
    if not os.path.exists(artdefaultpath) or not os.path.isdir(artdefaultpath):
        logging_system("{0} directory load error.".format(artdefaultpath), True, True)

    global default_content
    for root, dirs, files in os.walk(artdefaultpath):
        for file in files:
            if not file.startswith(".") and file.endswith(".html"):
                tmp = open(os.path.join(artdefaultpath, file), 'r')
                default_content.append(tmp.read().strip())
                tmp.close()

    if len(default_content) == 0:
        logging_system("default html content not exist.", True, True)


    # Hunting
    if hunt_enable:
        huntrulefile = os.path.join(artpath, "huntrules.txt")
        if not os.path.exists(huntrulefile) or not os.path.isfile(huntrulefile):
            logging_system("{0} file load error.".format(huntrulefile), True, True)

        with open(huntrulefile, 'r') as f:
            for line in f:
                line = line.rstrip()
                if len(line) > 0:
                    hunt_rules.append(line)

    # Syslog
    if syslog_enable:
        try:
            sport = int(syslogport)
        except ValueError:
            logging_system("syslogport({0}) not valid.".format(syslogport), True, True)
        try:
            handler = logging.handlers.SysLogHandler(address=(syslogserver, int(sport)),
                                                    facility=16, # facility 16: local0
                                                    socktype=socket.SOCK_STREAM)
            logger.addHandler(handler)
        except TimeoutError:
            logging_system("syslog tcp connection timed out. Wrong hostname/port? ({0}:{1})".format(syslogserver, sport), True, True)


if __name__ == '__main__':
    random.seed(datetime.now())

    try:
        config_load()
    except Exception:
        print(traceback.format_exc())
        sys.exit(1)
    logging_system("WOWHoneypot(version {0}) start. {1}:{2} at {3}".format(WOWHONEYPOT_VERSION, ip, port, get_time()), False, False)
    logging_system("Hunting: {0}".format(hunt_enable), False, False)
    myServer = WOWHoneypotHTTPServer((ip, port), WOWHoneypotRequestHandler)
    myServer.timeout = timeout
    try:
        myServer.serve_forever()
    except KeyboardInterrupt:
        pass

    myServer.server_close()
