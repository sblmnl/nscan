#!/usr/bin/python3

"""
	nscan
	Port scanner that utilizes multi-threading with concurrent scan capabilities
	
	!!! DISCLAIMER !!!
	This program is to be used on networks/devices that YOU own or have rights to.
	
	Author: https://github.com/sblmnl
	License: MIT
	Date Created: 2019-03-26 (YYYY-MM-DD)
"""

import os
import sys
import time
import json
import socket
import psutil
import binascii
import datetime
import ipaddress
from threading import Thread
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class ServiceScan(object):
    def _find_workers_by_value(self, list, var, val):
        results = []
        for i in range(len(list)):
            if list[i]["%s" % var] == val:
                results.append(i)
        return results

    def _check_port(self, target, service):
        result = { "host": target, "service": service, "status": False }

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            sock.connect((target, service["port"]))
            result["status"] = True
        except:
            result["status"] = False

        sock.close()
        return result

    def _get_unique_id(self):
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(str(datetime.datetime.utcnow()).encode("utf-8"))
        digest.update(os.urandom(4))
        buffer = digest.finalize()
        return binascii.hexlify(buffer).decode("utf-8")

    def _start_worker(self, id):
        # get worker object from running list
        i = self._find_workers_by_value(self.pool, "id", id)[0]

        if (self.pool[i]["status"] == "stop"): return

        # set worker as active
        self.pool[i]["status"] = "active"

        if (self.pool[i]["status"] == "stop"): return

        # run worker operation
        output = self._check_port(self.pool[i]["args"]["host"], self.pool[i]["args"]["service"])

        # write worker output
        f = open("scans/%s/temp/%s" % (self.id, id), "w+")
        f.write(json.dumps(output))
        f.close()

        # mark worker as finished and move to completed list
        self.pool[i]["status"] = "finished"

    def compile(self):
        print("compiling outputs...")
        base_path = "scans/%s" % self.id
        items = os.listdir("%s/temp" % base_path)
        for item in items:
            if os.path.isfile("%s/temp/%s" % (base_path, item)):
                f_input = open("%s/temp/%s" % (base_path, item), "r")
                data = json.loads(f_input.read())
                f_input.close()
                self.output["results"][data["host"]].append({
                    "service": str(data["service"]["service"]),
                    "port": int(data["service"]["port"]),
                    "status": bool(data["status"])
                })
                os.remove("%s/temp/%s" % (base_path, item))
        os.rmdir("%s/temp" % base_path)
        f_output = open("scans/%s/output.json" % self.id, "a+")
        f_output.write(json.dumps(self.output))
        f_output.close()
        self.end = time.time()
        self.elapsed = self.end - self.begin
        print("scanned %d targets for %d services in %d seconds!" % (
            len(self.targets),
            len(self.services),
            self.elapsed
        ))
        print("scan id: %s" % self.id)

    def stop(self):
        print("stopping workers...")
        self.status = "stop"
        for i in range(0, len(self.pool)):
            self.pool[i]["status"] = "stop"
        self.compile()

    def start(self):
        self.begin = time.time()
        print("creating directories...")
        if not os.path.exists("scans/%s/temp" % self.id):
            os.makedirs("scans/%s/temp" % self.id)

        id = 0
        total_workers = len(self.targets) * len(self.services)
        print("scanning %d hosts for %d services (%d workers)..." % (
            len(self.targets),
            len(self.services),
            total_workers
        ))

        for target in self.targets:
            if self.status == "stop": break
            for service in self.services:
                if self.status == "stop": break
                worker = { "id": None, "thread": None, "args": {}, "output": None, "status": None }
                worker["id"] = str(id)
                worker["args"] = { "host": target, "service": service }
                worker["thread"] = Thread(target=self._start_worker, args=(worker["id"],))
                worker["status"] = "inactive"
                if len(self.pool) < self.maximum_pool_size and id < total_workers - 1:
                    self.pool.append(worker)
                else:
                    for worker in self.pool:
                        worker["thread"].start()

                    while True:
                        if self.status == "stop": break

                        finished = len(
                            self._find_workers_by_value(
                                list=self.pool,
                                var="status",
                                val="finished"
                            )
                        )

                        if finished == len(self.pool): break
                        else: time.sleep(1)

                    self.pool = []
                    if id == total_workers - 1:
                        print("stopping...")
                        break
                id += 1
        print("finished!")

        self.compile()

    def __init__(self, targets, services):
        self.id = self._get_unique_id()
        self.targets = targets
        self.services = services
        self.status = "active"
        self.pool = []
        self.maximum_pool_size = (psutil.cpu_count() ** 2) * 8
        self.output = {
            "id": "%s" % self.id,
            "timestamp": "%s" % datetime.datetime.utcnow(),
            "results": {}
        }
        for target in self.targets:
            self.output["results"][str(target)] = []

def main(args):
    scan = None
    try:
        if len(args) != 3:
            args = [None] * 3
            args[0] = sys.argv[0]
            args[1] = input("enter a list of targets (ex. 192.168.1.0/24,127.0.0.1): ")
            args[2] = input("enter a path to a json list of services to scan: ")

        targets = []
        services = []

        tmp = args[1].split(",")
        for target in tmp:
            if "/" in target:
                for addr in ipaddress.IPv4Network(target):
                    targets.append(str(addr))
            else:
                targets.append(target)

        tmp = open(args[2], "r")
        services = json.loads(tmp.read())
        tmp.close()
        tmp = None

        scan = ServiceScan(targets, services)
        scan.start()
        return 0
    except KeyboardInterrupt:
        scan.stop()
    except Exception as e:
        print(e)
        return 1

sys.exit(main(sys.argv))
