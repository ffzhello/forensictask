#!/usr/bin/env python
# -*- coding=utf-8 -*-

#############################################################################
#  Author : zrwang
#  Date :
# 3/5/2017 v0.0.2 添加警报白名单，白名单内的警报不写入最终的IDS融合警报中
# 1/11/2016 v0.0.1
#
#  Program:
#    For Suricata: Convert eve.json to simple alert format.
#    For Bro: Convert weird.log to simple alert format.
##############################################################################
import json
import datetime
import os
import getopt

import sys


class SimpleAlert:
    def __init__(self, ts, srcip, srcport,
                 destip, destport, proto, sensortype, signature, count=1):
        self.ts = ts
        self.srcip = srcip
        self.srcport = srcport
        self.destip = destip
        self.destport = destport
        self.proto = proto
        self.sensortype = sensortype
        self.signature = signature
        self.count = count

    def __str__(self):
        return "{0:30}{1:20}{2:10}{3:20}{4:10}{5:8}{6:20}{7:45}{8:10}".format(
            self.ts, self.srcip, str(self.srcport), self.destip, str(self.destport),
            self.proto, self.sensortype, self.signature, str(self.count))

    # def toJSON(self):
    #    return json.dumps(self, default=lambda o: o.__dict__,
    #                      sort_keys=False, indent=4)


class AlertConverter:
    WHITE_LIST_FILE = "./AlertWhiteList.txt"

    def __init__(self, white_list_file=WHITE_LIST_FILE):
        self.white_list = []
        self.load_white_list(white_list_file)

    def load_white_list(self, infile=WHITE_LIST_FILE):
        with open(infile, "rb") as f:
            for line in f:
                self.white_list.append(line.strip(os.linesep))
        # print self.white_list

    def suricata_to_simple(self, infile, outfile):
        with open(infile, "rb") as f:
            with open(outfile, "ab") as outf:
                for line in f:
                    alert_content = json.loads(line)
                    # 判断当前警报是否在白名单中
                    alert_signature = None
                    try:
                        alert_signature = alert_content["alert"]["signature"].replace(" ", "_")
                    except KeyError as e:
                        print e
                    if not alert_signature or alert_signature in self.white_list:
                        continue
                    dt = datetime.datetime.strptime(alert_content["timestamp"], "%Y-%m-%dT%H:%M:%S.%f+0800")
                    # ts = time.mktime(dt.timetuple()) + dt.microsecond / 1000000.0
                    ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
                    try:
                        simple_alert = SimpleAlert(ts, alert_content["src_ip"],
                                                   alert_content["src_port"], alert_content["dest_ip"],
                                                   alert_content["dest_port"],
                                                   alert_content["proto"], "Suricate", alert_signature)
                        outf.write(simple_alert.__str__() + "\n")
                    except KeyError as e:
                        print e

    def bro_to_simple(self, infile, outfile):
        with open(infile, "rb") as f:
            with open(outfile, "ab") as outf:
                for line in f:
                    if line[0] == '#':
                        continue
                    list = line.split()
                    # 判断当前警报是否在白名单中
                    if list[6] in self.white_list:
                        continue
                    dt = datetime.datetime.fromtimestamp(float(list[0]))
                    ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
                    try:
                        simple_alert = SimpleAlert(ts, list[2], list[3],
                                                   list[4], list[5], "-", "Bro", list[6])
                        outf.write(simple_alert.__str__() + "\n")
                    except Exception as e:
                        print str(e)

    def do_full_convert(self, parent_dir, simple_alert_file):
        """

        :param parent_dir: the parent of the alert subdirectories to be converted.
        :return:
        """
        if not parent_dir or not simple_alert_file:
            sys.exit(2)

        suricata_detect_path = os.path.join(parent_dir, "suricata_detect")
        bro_detect_path = os.path.join(parent_dir, "bro_detect")

        with open(simple_alert_file, "wb") as outf:
            outf.write("{0:30}{1:20}{2:10}{3:20}{4:10}{5:8}{6:20}{7:45}{8:10}\n".format(
                "AlertTimeStamp", "SrcIP", "SrcPort", "DstIP", "DstPort", "Proto", "AlertSensorType",
                "AlertSignature", "AlertCount"))

        # Convert eve.json to simple alert format.
        eve_file = os.path.join(suricata_detect_path, "eve.json")
        if os.path.exists(eve_file):
            self.suricata_to_simple(eve_file, simple_alert_file)

        # Convert weired.log to simple alert format.
        weired_file = os.path.join(bro_detect_path, "weird.log")
        if os.path.exists(weired_file):
            self.bro_to_simple(weired_file, simple_alert_file)

    @staticmethod
    def usage():
        print "To be Completed!"
        pass

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:o:t:", ["help", "input_dir=", "output_file=", "ticketid="])
    except getopt.GetoptError as err:
        print str(err)
        AlertConverter.usage()
        sys.exit(2)
    input_dir = None
    ticketid = None
    output_file = None

    for o, a in opts:
        if o in ("-h", "--help"):
            AlertConverter.usage()
            sys.exit()
        elif o in ("-i", "--input_dir"):
            input_dir = a
        elif o in ("-o", "--output_file"):
            output_file = a
        # elif o in ("-t", "--ticketid"):
        #    ticketid = a
        else:
            assert False, "unhandled option"

    alert_converter = AlertConverter()
    alert_converter.do_full_convert(input_dir, output_file)
    # alert_converter.do_full_convert("E:\\AlertConverter\\9739\\", ".\\SimpleAlert.txt")
    # alert_converter.do_full_convert("/home/monster/test_data/9739", "./SimpleAlert.txt")

