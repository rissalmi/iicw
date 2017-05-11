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
mul = 0
par = 0
id = ""
okeyv = []
keyv = []
okeyindex = 0
keyindex = 0

def encrypt(src):
	global okeyindex

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
		print("encrypt: encrypted string: {}".format(repr_hex(dst)))
	return dst

def decrypt(src, length):
	global keyindex

	dst = ""
	if debug:
		print("decrypt: using keyv[{}] ({})".format(keyindex,
		    keyv[keyindex]))
	for i in range(0, length):
		dst += chr(ord(src[i]) ^ ord(keyv[keyindex][i]))
	keyindex += 1
	if debug:
		print("decrypt: decrypted string: {}".format(dst))
		print("decrypt: decrypted string: {}".format(repr_hex(dst)))
	return dst

# TODO: This function is only for testing the ENC feature.
# Decrypts the encrypt()'ed string with the same key as encrypt() used, which
# obviously results in the string that was given to encrypt() to encrypt.
def decrypto(src):
	dst = ""
	for a, b in zip(src, okeyv[okeyindex - 1]):
		dst += chr(ord(a) ^ ord(b))
	if debug:
		print("decrypto: decrypted string: {}".format(dst))
		print("decrypto: decrypted string: {}".format(repr_hex(dst)))
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
	print("type(src): {}".format(type(src)))
	for c in src:
		#a = c
		#print("type(c): {}".format(type(c)))
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
		if debug >= 2:
			print("parity_ok: {}".format(hex(a)), end="")
		prt_bit = a & 1
		a >>= 1
		dst += chr(a)
		if debug >= 2:
			print(" -> {} ({})".format(hex(a), chr(a)))
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
			print("run: type(content) after recv: {}".format(type(content)))
			if not par:
				tmp = tmp.decode()
			if eom == 1:
				print(tmp)
				return
			if par:
				print("run: type(tmp) before parity_ok: {}".format(type(tmp)))
				state, dst = parity_ok(tmp)
				print("run: type(tmp) after parity_ok: {}".format(type(tmp)))
				print("run: type(dst) after parity_ok: {}".format(type(dst)))
				if state:
					print("parity ok")
					tmp = dst
					print("type(tmp) after assignation: {}".format(type(tmp)))
				else:
					print("parity not ok")
					s.send(udp_pack("Send again".encode(), 10, ack=0))
					keyindex += 1
					okeyindex += 1
					continue
			if debug:
				print("run: tmp after parity_ok: {}".format(" ".join(hex(ord(n)) for n in tmp)))
			if enc:
				if debug:
					print("run: tmp before decryption: {}"
					    .format(repr_hex(tmp)))
				tmp = decrypt(tmp, length)
				if debug:
					print("run: decrypted tmp: {}"
					    .format(tmp))
			else:
				tmp = tmp.rstrip('\0')
			content += tmp
			if rem == 0:
				break
		#content = content.decode()
		if debug:
			print("run: type(content) after receiving all: {}".format(type(content)))
			print("len(content) = {}".format(len(content)))
			print("run: content before reversing: {}".format(content))
		content = " ".join(content.split()[::-1])
		if debug:
			print("run: reversed content: {}".format(content))
			print("run: reversed content as hex: {}".format(repr_hex(content)))
		#if enc:
		#	content = encrypt(content)
			#if debug:
			#	print("run: decrypto returned: {}"
			#	    .format(decrypto(content)))
		rem = len(content)
		for piece in pieces(content):
			length = len(piece)
			rem -= length
			print("run: length = {}, rem = {}, piece = {}".format(length, rem, piece))
			if enc:
				print("run: type(piece) before encrypt: {}".format(type(piece)))
				piece = encrypt(piece)
				print("run: type(piece) after encrypt: {}".format(type(piece)))
			piece = piece.encode()
			if par:
				print("run: type(piece) before parity_add: {}".format(type(piece)))
				piece = parity_add(piece)
				#print("run: type(content) after parity_add: {}".format(type(content)))
				print(piece, len(piece))
				#print("run: content after parity_add: {}".format(" ".join(hex(ord(n)) for n in content)))
				print(type(piece))
			omsg = udp_pack(piece, length, rem=rem)
			try:
				s.send(omsg)
			except:
				print("send")
				sys.exit(1)

def server_parse(s):
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
	if mul:
		buf += " MUL"
	if par:
		buf += " PAR"
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
	buf = buf.encode()
	if par:
		buf = parity_add(buf)
	data = udp_pack(buf, len(buf))
	try:
		s.send(data)
	except:
		print("send")
		sys.exit(1)

def udp_pack(buf, length, ack=1, rem=0):
	print("udp_pack: type(buf) before struct.pack: {}".format(type(buf)))
	print("udp_pack: buf: {}".format(buf))
	data = struct.pack(STRUCTFMT, id.encode(), ack, 0, rem, length,
	    buf)
	return data

def udp_unpack(data):
	return struct.unpack(STRUCTFMT, data)

def usage():
	print("usage: {} [-empv] host port".format(argv0))
	sys.exit(1)

def main():
	global argv0, debug, enc, mul, par

	argv0 = sys.argv[0]
	try:
		options, argv = getopt.getopt(sys.argv[1:], "empv")
	except getopt.GetoptError:
		usage()
	for option in options:
		if debug:
			print("main: option: {}".format(option))
		if option[0] == '-e':
			enc = 1
		elif option[0] == '-m':
			mul = 1
		elif option[0] == '-p':
			par = 1
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
