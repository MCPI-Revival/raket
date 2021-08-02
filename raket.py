#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  main.py
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
import struct
import time
from rak import RakNet

server_prefix = "MCCPP;Demo;";
server_name = "Raket Server";
server_id = b"\x00\x00\x00\x00\x00\x1f\x10\x00";
server_port = 19134;

entities = 0;
queue = bytes();

raknet = RakNet();

def decode_packet(data):
	try:
		if data[4] == 0x00:
			packet = {
				"iteration": data[1],
				"encapsulation": data[4],
				"length": int(struct.unpack("!H", data[5:7])[0] / 8),
				"id": data[7],
				"data": data[8:-1] + bytes([data[-1]]),
				"error": None
			};
		elif data[4] == 0x40:
			packet = {
				"iteration": data[1],
				"encapsulation": data[4],
				"length": int(struct.unpack("!H", data[5:7])[0] / 8),
				"id": data[10],
				"data": data[11:-1] + bytes([data[-1]]),
				"error": None
			};
		elif data[4] == 0x60:
			packet = {
				"iteration": data[1],
				"encapsulation": data[4],
				"length": int(struct.unpack("!H", data[5:7])[0] / 8),
				"id": data[14],
				"data": data[15:-1] + bytes([data[-1]]),
				"error": None
			};
		else:
			packet = {
				"error": "invalid"
			};
	except IndexError:
		packet = {
			"error": "invalid"
		};
	return packet;

def encode_packet(encapsulation, id, data, iterations):
	packet = bytes();
	template = b"\x84" + bytes([iterations & 0xff]) + bytes([(iterations >> 8) & 0xff]) + bytes([(iterations >> 16) & 0xff]) + bytes([encapsulation]) + struct.pack("!H", (len(data) + 1) * 8);
	if encapsulation == 0x00:
		packet = template + data;
	elif encapsulation == 0x40:
		packet = template + b"\x00\x00\x00" + bytes([id]) + data;
	elif encapsulation == 0x60:
		packet = template + b"\x00\x00\x00\x00\x00\x00\x00" + bytes([id]) + data;
	return packet;

def raw_packet(id, data, iterations):
	packet = b"\x84" + bytes([iterations & 0xff]) + bytes([(iterations >> 8) & 0xff]) + bytes([(iterations >> 16) & 0xff]) + b"\x00" + struct.pack("!H", (len(data) + 1) * 8) + bytes([id]) + data;
	return packet;

def encode_pos(pos):
	# x, y, z
	return struct.pack("!f", 128 + pos[0]) + struct.pack("!f", 64 + pos[1]) + struct.pack("!f", 128 + pos[2]);

def decode_pos(pos):
	return [struct.unpack("!f", pos[:4])[0] - 128, struct.unpack("!f", pos[4:8])[0] - 64, struct.unpack("!f", pos[8:12])[0] - 128];

def encode_string(data):
	return struct.pack("!H", len(data)) + bytes(data, "utf-8");

def encode_pitch_yaw(pitch_yaw):
	return struct.pack("!H", pitch_yaw[0]) + struct.pack("!H", pitch_yaw[1]);

def decode_pitch_yaw(pitch_yaw):
	return [struct.unpack("!H", pitch_yaw[:2])[0], struct.unpack("!H", pitch_yaw[2:4])[0]];

def broadcast(data, ex=set()):
	for i in raknet.get_addrs():
		uid = raknet.get_uid(i);
		if not uid in ex and raknet.players[uid]["entity_id"] != None:
			new_packet = b"\x84" + bytes([raknet.players[uid]["iterations"]]) + data[2:];
			raknet.sendto(new_packet, i);
			plus(uid, new_packet);
	return 0;

def spawn_entities(addr):
	uid = raknet.get_uid(addr);
	new_packet = raw_packet(0x89, raknet.players[uid]["client_id"] + encode_string(raknet.players[uid]["username"]) + struct.pack("!I", raknet.players[uid]["entity_id"]) + encode_pos([0, 4, 0]) + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00\x00\x00\x7f" + b"\x00", 0);
	broadcast(new_packet, [uid]);
	for i in raknet.players:
		print(i);
		if i != uid:
			new_packet = raw_packet(0x89, raknet.players[i]["client_id"] + encode_string(raknet.players[i]["username"]) + struct.pack("!I", raknet.players[i]["entity_id"]) + encode_pos(raknet.players[i]["pos"]) + encode_pitch_yaw(raknet.players[i]["pitch_yaw"]) + b"\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00\x00\x00\x00\x00\x00\x00\x00\x7f" + b"\x00", 0);
			raknet.sendto(new_packet, addr);
			plus(uid, new_packet);

	new_packet = raw_packet(0x85, encode_string("Welcome to " + server_name + ", " + raknet.players[uid]["username"] + "!"), raknet.players[uid]["iterations"]);
	raknet.sendto(new_packet, addr);
	return 0;

def plus(uid, packet):
	raknet.players[uid]["last_packet"] = packet;
	raknet.players[uid]["iterations"] += 1;

def handler(data, addr, socket):
	global entities;
	global queue;
	uid = raknet.get_uid(addr);
	if data[0] == 0xa0:
		old_packet = decode_packet(raknet.players[uid]["last_packet"]);
		if old_packet["error"] == None:
			raknet.sendto(raw_packet(old_packet["id"], old_packet["data"], raknet.players[uid]["iterations"]), addr);
		else:
			raknet.sendto(raknet.players[uid]["last_packet"], addr);
	else:
		packet = decode_packet(data);
		new_packet = None;
		if packet["id"] != 0x00:
			new_packet = b"\xc0\x00\x01\x01" + bytes([packet["iteration"]]) + b"\x00\x00";
			socket.sendto(new_packet, addr);
		if packet["id"] == 0x09:
			raknet.players[uid]["session"] = data[-8:];
			new_packet = raw_packet(0x10, b"\x04\x3f\x57\xfe\xcd" + struct.pack("!H", server_port) + b"\x00\x00\x04\xf5\xff\xff\xf5\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00\x04\xff\xff\xff\xff\x00\x00" + raknet.players[uid]["session"] + b"\x00\x00\x00\x00\x04\x44\x0b\xa9", raknet.players[uid]["iterations"]);
			socket.sendto(new_packet, addr);
		elif packet["id"] == 0x82:
			username = packet["data"][2:2 + struct.unpack("!H", packet["data"][:2])[0]].decode("utf-8");
			raknet.players[uid]["username"] = username;
			new_packet = encode_packet(0x60, 0x83, b"\x00\x00\x00\x00", raknet.players[uid]["iterations"]);
			socket.sendto(new_packet, addr);
			plus(uid, new_packet);
			new_packet = encode_packet(0x60, 0x87, b"\x01\x02\x03\x04\x00\x00\x00\x00\x00\x00\x00\x01" + struct.pack("!I", entities + 1) + encode_pos([0, 4, 0]), raknet.players[uid]["iterations"]);
			socket.sendto(new_packet, addr);
			entities += 1;
			raknet.players[uid]["entity_id"] = entities;
		elif packet["id"] == 0x84:
			if packet["data"][0] == 0x01:
				spawn_entities(addr);
		elif packet["id"] == 0x94:
			if uid in raknet.players and struct.unpack("!I", packet["data"][:4])[0] == raknet.players[uid]["entity_id"]:
				broadcast(data, [uid]);
				raknet.players[uid]["pos"] = decode_pos(packet["data"][4:16]);
				raknet.players[uid]["pitch_yaw"] = decode_pitch_yaw(packet["data"][16:20]);
		elif packet["id"] == 0x15:
			del raknet.players[uid];
		elif packet["id"] == 0x00 and packet["encapsulation"] == 0x40:
			try:
				new_packet = raw_packet(0x86, struct.pack("!l", 0x00), raknet.players[uid]["iterations"]);
				socket.sendto(new_packet, addr);
			except:
				pass;
		if new_packet != None and uid in raknet.players:
			plus(uid, new_packet);
	return 0;

def main(args):
	raknet.set_option("name", server_prefix + server_name);
	raknet.set_option("id", server_id);
	raknet.set_option("port", server_port);
	raknet.set_option("custom_packets", [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0xa0]);
	raknet.set_option("custom_handler", handler);
	# Uncomment this to enable ("verbose") debugging:
	# raknet.set_option("debug", True);
	try:
		raknet.run();
	except KeyboardInterrupt:
		return 0;

if __name__ == '__main__':
	sys.exit(main(sys.argv));
