#!/usr/bin/env python3.4
import random
import socket
import struct
import sys

KEYC = 20
KEYLEN = 64
RCVLEN = 8192
STRUCTFMT = '!8s??HH64s'

id = ""
okeyv = []
keyv = []
okeyindex = 0
keyindex = 0

def encrypt(src):
	global okeyindex

	dst = ""
	for a, b in zip(src, okeyv[okeyindex]):
		dst += chr(ord(a) ^ ord(b))
	okeyindex += 1
	return dst

def decrypt(src, length):
	global keyindex

	dst = ""
	for i in range(0, length):
		dst += chr(ord(src[i]) ^ ord(keyv[keyindex][i]))
	keyindex += 1
	return dst

def initconn(host, port):
	global id

	s = socket_init(host, port, socket.SOCK_STREAM)
	id, port = tcp_negotiate(s)
	s.close()
	s = socket_init(host, port, socket.SOCK_DGRAM)
	udp_hello(s)
	return s

def key_generate():
	dst = ""
	for i in range(0, KEYLEN):
		n = random.choice([random.randint(0, 9), random.randint(17, 22),
		    random.randint(49, 54)])
		dst += chr(n + 48)
	return str(dst)

def parity_add(src):
	dst = b''
	for c in src:
		c <<= 1
		c += parity_get(c)
		dst += bytes([c])
	return dst

def parity_get(n):
	while n > 1:
		n = (n >> 1) ^ (n & 1)
	return n

def parity_ok(src):
	dst = ""
	for c in src:
		if isinstance(c, int):
			a = c
		else:
			a = ord(c)
		prt_bit = a & 1
		a >>= 1
		dst += chr(a)
		if prt_bit != parity_get(a):
			return False, dst
	return True, dst

def pieces(msg, length=64):
	return [ msg[i:i+length] for i in range(0, len(msg), length) ]

def repr_hex(p):
	return " ".join(hex(ord(n)) for n in p)

def run(s):
	global keyindex, okeyindex
	while True:
		content = ""
		while True:
			try:
				data = s.recv(RCVLEN)
				cid, ack, eom, rem, length, tmp = udp_unpack(data)
			except OSError as e:
				print("recv: {}".format(str(e)))
				sys.exit(1)
			if eom == 1:
				print(tmp.decode())
				return
			state, dst = parity_ok(tmp)
			if state:
				tmp = dst
			else:
				if rem == 0:
					s.send(udp_pack("Send again".encode(), 10, ack=0))
					okeyindex += 1
				keyindex += 1
				continue
			tmp = decrypt(tmp, length)
			content += tmp
			if rem == 0:
				break
		content = " ".join(content.split()[::-1])
		rem = len(content)
		for piece in pieces(content):
			length = len(piece)
			rem -= length
			piece = encrypt(piece)
			piece = piece.encode()
			piece = parity_add(piece)
			omsg = udp_pack(piece, length, rem=rem)
			try:
				s.send(omsg)
			except:
				sys.exit(1)

def server_parse(s):
	try:
		buf = s.recv(RCVLEN).decode()
	except:
		sys.exit(1)
	buf = buf.strip(' \r\n\0').split('\r\n')
	line = buf[0].split(' ')
	if (line[0] != "HELLO"):
		print("server returned garbage")
		sys.exit(1)
	id = line[1]
	port = line[2]
	for line in buf[1:]:
		if line[0] == '.':
			break
		keyv.append(line)
	return id, port

def socket_init(host, port, type):
	try:
		res0 = socket.getaddrinfo(host, None, type=type)
	except socket.gaierror as e:
		print(e)
		sys.exit(1)
	for res in res0:
		try:
			s = socket.socket(res[0], res[1], res[2])
		except OSError as e:
			print(e)
			continue
		try:
			s.connect((res[4][0], int(port)))
		except socket.timeout:
			print("socket timeout")
			sys.exit(1)
		break
	return s

def tcp_negotiate(s):
	buf = "HELLO ENC MUL PAR\r\n"
	for i in range(0, KEYC):
		okeyv.append(key_generate())
		buf += okeyv[i]
		buf += "\r\n"
	buf += ".\r\n"
	try:
		s.send(buf.encode())
	except:
		print("send")
		sys.exit(1)
	id, port = server_parse(s)
	return id, port

def udp_hello(s):
	buf = "Hello from " + id
	buf = encrypt(buf)
	buf = buf.encode()
	buf = parity_add(buf)
	data = udp_pack(buf, len(buf))
	try:
		s.send(data)
	except:
		print("send")
		sys.exit(1)

def udp_pack(buf, length, ack=1, rem=0):
	data = struct.pack(STRUCTFMT, id.encode(), ack, 0, rem, length,
	    buf)
	return data

def udp_unpack(data):
	return struct.unpack(STRUCTFMT, data)

def usage():
	print("usage: {} host port".format(argv0))
	sys.exit(1)

def main():
	global argv0

	argv0 = sys.argv[0]
	try:
		argv = sys.argv[1:]
	except:
		usage()
	try:
		host = argv[0]
		port = argv[1]
	except:
		usage()
	s = initconn(host, port)
	run(s)
	s.close()

if __name__ == "__main__":
	main()
