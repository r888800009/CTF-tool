#!/usr/bin/env python
def concat(str1):
	return 'concat({})'.format(','.join([hex(ord(x)) for x in list(str1)]))
