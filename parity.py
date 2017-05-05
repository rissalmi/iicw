def parity_add(src):
	dst = ""
	for c in src:	
		a = ord(c)
		a <<= 1
		a += parity_get(a)
		dst += chr(a)
	return dst

def parity_get(n):
	while n > 1:
		n = (n >> 1) ^ (n & 1)
	return n

def parity_ok(src):
	dst = ""
	for c in src:
		a = c
		prt_bit = a & 1
		a >>= 1
		dst += chr(a)
		if prt_bit != parity_get(a):
			return False, dst
	return True, dst