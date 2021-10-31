#!/usr/bin/env python
def urlencode_all(str):
  ans = ''
  for c in str:
    ans += '%' + hex(ord(c))[2:]
  return ans

