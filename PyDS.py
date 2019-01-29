#!/usr/bin/python

import os
from subprocess import Popen, PIPE, STDOUT
from time import sleep
from datetime import datetime
import re

class bcolors:
    IP = '\033[93m' + '\033[1m'
    PROC = '\033[94m' + '\033[1m'
    STATE = '\033[92m' + '\033[1m'
    PASSWD = '\033[91m' + '\033[1m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

log = {
	"network_conn_state": [],
	"passwd": [],
	"shadow": [],
	"w": [],
	"group": []
	}


def alert(type, msg):
	s = ""
	if type == "network":
		msg = re.sub(' +', ' ', msg).strip()
		if not msg:
			return
		msg = msg.split(' ')
		if len(msg) == 6:
			msg.append(msg[5])
			msg[5] = "-"
		if msg[5] == "TIME_WAIT" or msg[5] == "TIME_CLOSE":
			return
		if msg[5] == "LISTEN" or msg[5] == "-":
			s = "NEW SOCKET OPENED on   " + bcolors.IP + msg[3].ljust(20) +\
			bcolors.ENDC + " by PROCESS   " + bcolors.PROC + msg[6].ljust(20) +\
			"   " + bcolors.STATE + msg[5] + bcolors.ENDC
		else:
			s = "NEW CONNECTION from    " + bcolors.IP + msg[4].ljust(20) +\
			bcolors.ENDC + " on PROCESS   " + bcolors.PROC + msg[6].ljust(20) +\
			"   " + bcolors.STATE + msg[5] + bcolors.ENDC
	elif type == "passwd":
		s = bcolors.PASSWD + "PASSWD FILE CHANGED: " + bcolors.STATE + msg + bcolors.ENDC
	elif type == "shadow":
		s = bcolors.PASSWD + "SHADOW FILE CHANGED: " + bcolors.STATE + msg + bcolors.ENDC
	elif type == "group":
		s = bcolors.PASSWD + "GROUP FILE CHANGED: " + bcolors.STATE + msg + bcolors.ENDC
	elif type == "sudoers":
		s = bcolors.PASSWD + "SUDOERS FILE CHANGED: " + bcolors.STATE + msg + bcolors.ENDC
	elif type == "w":
		msg = re.sub(' +', ' ', msg).strip()
		s = bcolors.PASSWD + "REMOTE LOGIN: " + bcolors.IP + msg + bcolors.ENDC + "        "

	print("\n" + bcolors.UNDERLINE + " "*(len(s)-30) + bcolors.ENDC)
	print(s)
	print(bcolors.UNDERLINE + " "*(len(s)-30) + bcolors.ENDC)
	f = open("/root/PyDS.log","a")
	f.write(str(datetime.now()) + ' - ')
	f.write(s)
	f.write("\n")
	f.close()


def check_netstat():
	global log
	output = Popen(['netstat', '-nutlap'], stdout=PIPE, stderr=STDOUT).communicate()[0]
	network_conn_state = output.strip().split("\n")[2:]
	for conn in network_conn_state:
		if conn not in log["network_conn_state"]:
			alert("network", conn)
			log["network_conn_state"].append(conn)
	for conn in log["network_conn_state"]:
		if conn not in network_conn_state:
			log["network_conn_state"].remove(conn)

def load_passwd():
	global log
	log["passwd"] = []
	f = open("/etc/passwd", 'r')
	lines = f.readlines()
	f.close()
	for line in lines:
		line = line.strip()
		log["passwd"].append(line)

def load_shadow():
	global log
	log["shadow"] = []
	f = open("/etc/shadow", 'r')
	lines = f.readlines()
	f.close()
	for line in lines:
		line = line.strip()
		log["shadow"].append(line)

def load_group():
	global log
	log["group"] = []
	f = open("/etc/group", 'r')
	lines = f.readlines()
	f.close()
	for line in lines:
		line = line.strip()
		log["group"].append(line)

def load_sudoers():
	global log
	log["sudoers"] = []
	f = open("/etc/sudoers", 'r')
	lines = f.readlines()
	f.close()
	for line in lines:
		line = line.strip()
		log["sudoers"].append(line)

def check_passwd():
	global log
	output = Popen(['cat', '/etc/passwd'], stdout=PIPE, stderr=STDOUT).communicate()[0]
	passwd = output.strip().split("\n")
	if not passwd == log["passwd"]:
		for i in range(len(passwd)):
			line = passwd[i]
			if line not in log["passwd"]:
				alert("passwd", "(line " + str(i+1) + ") " + line)
		load_passwd()

def check_shadow():
	global log
	output = Popen(['cat', '/etc/shadow'], stdout=PIPE, stderr=STDOUT).communicate()[0]
	shadow = output.strip().split("\n")
	if not shadow == log["shadow"]:
		for i in range(len(shadow)):
			line = shadow[i]
			if line not in log["shadow"]:
				alert("shadow", "(line " + str(i+1) + ") " + line)
		load_shadow()

def check_sudoers():
	global log
	output = Popen(['cat', '/etc/sudoers'], stdout=PIPE, stderr=STDOUT).communicate()[0]
	sudoers = output.strip().split("\n")
	if not sudoers == log["sudoers"]:
		for i in range(len(sudoers)):
			line = sudoers[i]
			if line not in log["sudoers"]:
				alert("sudoers", "(line " + str(i+1) + ") " + line)
		load_sudoers()

def check_group():
	global log
	output = Popen(['cat', '/etc/group'], stdout=PIPE, stderr=STDOUT).communicate()[0]
	group = output.strip().split("\n")
	if not group == log["group"]:
		for i in range(len(group)):
			line = group[i]
			if line not in log["group"]:
				alert("group", "(line " + str(i+1) + ") " + line)
		load_group()

def check_w():
	global log
	output = Popen(['w', '-his'], stdout=PIPE, stderr=STDOUT).communicate()[0]
	w = output.strip().split("\n")
	for line in w:
		if line not in log["w"]:
			alert("w", line)
			log["w"].append(line)
	for line in log["w"]:
		if line not in w:
			log["w"].remove(line)
		

def main():
	load_passwd()
	load_shadow()
	load_group()
	load_sudoers()
	pause = 0.1
	while True:
		check_netstat()
		sleep(pause)
		check_passwd()
		sleep(pause)
		check_shadow()
		sleep(pause)
		check_w()
		sleep(pause)
		check_group()
		sleep(pause)
		check_sudoers()
		sleep(pause)



main()

