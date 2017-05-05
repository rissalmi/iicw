#!/usr/bin/env python3.4
import getopt
import random
import socket
import struct
import sys

KEYC = 20
KEYLEN = 64
RCVLEN = 8192
STRUCTFMT = '!8s??HH64s'

debug = 0
enc = 0
id = ""
okeyv = []
keyv = []
okeyindex = 0
keyindex = 0

def encrypt(src):
	global debug, okeyindex, okeyv

	dst = ""
	if debug:
		print("encrypt: using okeyv[{}] ({})".format(okeyindex,
		    okeyv[okeyindex]))
	for a, b in zip(src, okeyv[okeyindex]):
		dst += chr(ord(a) ^ ord(b))
		if debug >= 2:
			print("encrypt: {} XOR {} -> {}".format(hex(ord(a)),
			    hex(ord(b)), hex(ord(dst[-1]))))
	okeyindex += 1
	if debug:
		print("encrypt: encrypted string: {}"
		    .format(" ".join(hex(ord(n)) for n in dst)))
	return dst

def decrypt(src, length):
	global debug, keyindex, keyv

	dst = ""
	if debug:
		print("decrypt: using keyv[{}] ({})".format(keyindex,
		    keyv[keyindex]))
	for i in range(0, length):
		dst += chr(ord(src[i]) ^ ord(keyv[keyindex][i]))
	keyindex += 1
	if debug:
		print("decrypt: decrypted string: {}".format(dst))
		print("decrypt: decrypted string: {}".format(" "
		    .join(hex(ord(n)) for n in dst)))
	return dst

# TODO: This function is only for testing the ENC feature.
# Decrypts the encrypt()'ed string with the same key as encrypt() used, which
# obviously results in the string that was given to encrypt() to encrypt.
def decrypto(src):
	global debug, okeyindex, okeyv

	dst = ""
	for a, b in zip(src, okeyv[okeyindex - 1]):
		dst += chr(ord(a) ^ ord(b))
	if debug:
		print("decrypto: decrypted string: {}".format(dst))
		print("decrypto: decrypted string: {}".format(" "
		    .join(hex(ord(n)) for n in dst)))
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
	global KEYLEN

	dst = ""
	for i in range(0, KEYLEN):
		n = random.choice([random.randint(0, 9), random.randint(17, 22),
		    random.randint(49, 54)])
		dst += chr(n + 48)
	return str(dst)

def run(s):
	global debug

	while True:
		try:
			data = s.recv(RCVLEN)
			cid, ack, eom, rem, length, content = udp_unpack(data)
		except:
			print("recv")
			sys.exit(1)
		if eom == 1:
			print(content.decode())
			return
		content = content.decode()
		if not enc:
			content.rstrip('\0\r\n')
		if enc:
			if debug:
				print("run: content before decryption: {}"
				    .format(" ".join(hex(ord(n)) for n in content)))
				for c in content:
					if ord(c) == 0:
						print("run: contains zero")
			content = decrypt(content, length)
			if debug:
				print("run: decrypted content: {}"
				    .format(content))
		content = " ".join(content.split()[::-1])
		if debug:
			print("run: reversed content: {}".format(content))
		if enc:
			content = encrypt(content)
			#if debug:
			#	print("run: decrypto returned: {}"
			#	    .format(decrypto(content)))
		omsg = udp_pack(content, length, 1)
		try:
			s.send(omsg)
		except:
			print("send")
			sys.exit(1)

def server_parse(s):
	global debug

	try:
		buf = s.recv(RCVLEN).decode()
	except:
		print("recv")
		sys.exit(1)
	if debug:
		print("server_parse: buf:\n{}".format(buf))
	buf = buf.strip(' \r\n\0').split('\r\n')
	line = buf[0].split(' ')
	if (line[0] != "HELLO"):
		print("server returned garbage")
		sys.exit(1)
	id = line[1]
	port = line[2]
	for line in buf[1:]:
		if debug:
			print("server_parse: len(line) = {}, line: {}"
			    .format(len(line), line))
		if line[0] == '.':
			break
		keyv.append(line)
	if debug:
		for key in keyv:
			print("server_parse: key: {}".format(key))
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
	buf = "HELLO"
	if enc:
		buf += " ENC"
	buf += "\r\n"
	if enc:
		for i in range(0, KEYC):
			okeyv.append(key_generate())
			buf += okeyv[i]
			buf += "\r\n"
		buf += ".\r\n"
	if debug:
		print("tcp_negotiate: buf:\n{}".format(buf))
	try:
		s.send(buf.encode())
	except:
		print("send")
		sys.exit(1)
	id, port = server_parse(s)
	return id, port

def udp_hello(s):
	buf = "Hello from " + id
	if enc:
		buf = encrypt(buf)
	data = udp_pack(buf, len(buf), 1)
	try:
		s.send(data)
	except:
		print("send")
		sys.exit(1)

def udp_pack(buf, length, ack):
	global STRUCTFMT

	data = struct.pack(STRUCTFMT, id.encode(), ack, 0, 0, length,
	    buf.encode())
	return data

def udp_unpack(data):
	global STRUCTFMT

	return struct.unpack(STRUCTFMT, data)

def usage():
	global argv0

	print("usage: {} [-ev] host port".format(argv0))
	sys.exit(1)

def main():
	global argv0, debug, enc

	argv0 = sys.argv[0]
	try:
		options, argv = getopt.getopt(sys.argv[1:], "ev")
	except getopt.GetoptError:
		usage()
	for option in options:
		if debug:
			print("main: option: {}".format(option))
		if option[0] == '-e':
			enc = 1
		elif option[0] == '-v':
			debug += 1
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
