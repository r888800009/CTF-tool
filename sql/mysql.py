#!/usr/bin/env python
def concat(str1):
	return 'concat({})'.format(','.join(['0x'+ str(ord(x)) for x in list(str1)]))
