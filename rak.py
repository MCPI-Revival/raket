#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  rak.py
#  
#  Copyright 2020 Alvarito050506 <donfrutosgomez@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 of the License.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

import sys
import socket
import struct
import time

class RakNet:
	def __init__(self):
		self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP);
		self.__options = {
			"addr": "0.0.0.0",
			"port": 19132,
			"name": "MCCPP;Demo;Rak.py Server",
			"id": b"\x10\x00\x10\x00\x10\x00\x10\x00",
			"magic": b"\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78",
			"custom_handler": lambda data, addr, socket: 0,
			"custom_packets": [0x84],
			"debug": False
		};
		self.players = dict();
		self.__packet_names = {
			0x01: "ID_CONNECTED_PING_OPEN_CONNECTIONS",
			0x02: "ID_UNCONNECTED_PING_OPEN_CONNECTIONS",
			0x05: "ID_OPEN_CONNECTION_REQUEST_1",
			0x06: "ID_OPEN_CONNECTION_REPLY_1",
			0x07: "ID_OPEN_CONNECTION_REQUEST_2",
			0x08: "ID_OPEN_CONNECTION_REPLY_2",
			0x1a: "ID_INCOMPATIBLE_PROTOCOL_VERSION",
			0x1c: "ID_UNCONNECTED_PING_OPEN_CONNECTIONS",
			0xa0: "NAK",
			0xc0: "ACK"
		};
		self.__addrs = set();
		self.__addr_to_uid = dict();
		self.__start = None;

	def set_option(self, name, value):
		if name in self.__options:
			self.__options[name] = value;
		else:
			raise NameError(name);
		return self.__options;

	def get_options(self):
		return self.__options;

	def get_uid(self, i):
		return bytes(str(i), "utf-8") + self.__addr_to_uid[i];

	def get_addrs(self):
		return self.__addrs;

	def sendto(self, packet, addr):
		return self.__socket.sendto(packet, addr);

	def __parse(self, data):
		if data[0] == 0x01 or data[0] == 0x02:
			return {
				"id": data[0],
				"timestamp": data[:8]
			};
		elif data[0] == 0x05:
			return {
				"id": data[0],
				"version": data[17],
				"mtu": len(data) - 18
			};
		elif data[0] == 0x07:
			return {
				"id": data[0],
				"cookie": data[16:21],
				"port": data[22:24],
				"mtu": data[25:27],
				"client_id": data[28:36]
			};
		elif data[0] == 0xc0 or data[0] == 0xa0:
			return {
				"id": data[0]
			};

	def __raw_packet(self, packet_id, packet):
		return bytes([packet_id]) + packet;

	def __handler(self, data, addr):
		packet = self.__parse(data);
		new_packet = None;
		if packet["id"] == 0x01 or packet["id"] == 0x02:
			new_packet = self.__raw_packet(0x1c, struct.pack("!d", time.time() - self.__start) + self.__options["id"] + self.__options["magic"] + b"\x00" + bytes([len(self.__options["name"])]) + bytes(self.__options["name"], "utf-8"));
			self.__socket.sendto(new_packet, addr);
		elif packet["id"] == 0x05:
			if packet["version"] == 5:
				new_packet = b"\x06" + self.__options["magic"] + self.__options["id"] + b"\x00" + packet["mtu"].to_bytes(3, "little");
				self.__socket.sendto(new_packet, addr);
			else:
				new_packet = b"\x1a\x05" + self.__options["magic"] + self.__options["id"];
				self.__socket.sendto(new_packet, addr);
		elif packet["id"] == 0x07:
			new_packet = b"\x08" + self.__options["magic"] + self.__options["id"] + bytes(self.__options["addr"], "utf-8") + packet["mtu"] + b"\x00";
			self.__socket.sendto(new_packet, addr);
			if addr not in self.__addrs:
				self.__addrs.add(addr);
			self.players[bytes(str(addr), "utf-8") + data[-8:]] = {
				"addr": addr,
				"last_packet": None,
				"iterations": 0,
				"entity_id": None,
				"username": None,
				"session": None,
				"client_id": data[-8:]
			};
			self.__addr_to_uid[addr] = data[-8:];
		if self.__options["debug"] == True:
			print("[C --> S]: " + self.__packet_names[packet["id"]]);
			if new_packet != None:
				print("[S --> C]: " + self.__packet_names[new_packet[0]]);
		return 0;

	def run(self):
		self.__socket.bind((self.__options["addr"], self.__options["port"]));
		self.__start = time.time();
		while True:
			data, addr = self.__socket.recvfrom(4096);
			if data[0] in self.__options["custom_packets"]:
				self.__options["custom_handler"](data, addr, self.__socket);
			else:
				self.__handler(data, addr);
