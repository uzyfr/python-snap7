import snap7
import os
import sys
import time

snap7.common.logger.disabled=True

def format_to_range(s):
    _rv=''
    if s == '*':
      _rv=(1, 255)
    elif s.find('-') == -1:
      _rv=(int(s), int(s)+1)
    elif s.find('-') != -1:
      _a, _b = s.split('-')
      _rv=(int(_a), int(_b)+1)
    return _rv


def expand_ips(_ips):
  s=set()
  for i in _ips:
    # Do stuff like expand '-', treat '*' or ','
    a,b,c,d=i.split('.')
    al, ah=format_to_range(a)
    bl, bh=format_to_range(b)
    cl, ch=format_to_range(c)
    dl, dh=format_to_range(d)
    for _a in xrange(al, ah):
      for _b in xrange(bl, bh):
        for _c in xrange(cl, ch):
          for _d in xrange(dl, dh):
            #print("{}.{}.{}.{}".format(_a, _b, _c, _d))
            s.add("{}.{}.{}.{}".format(_a, _b, _c, _d))
  return (len(s), s)


def scan(_target):
  c=snap7.client.Client()
  cpuinfo=''
  cpustate=''
  cpuordercode=''
  cpuprotection=''
  cpupassword=''
  try:
    c.connect(_target, 0, 0)
  except Exception as e:
    return True
  try:
    cpuinfo=c.get_cpu_info()
  except snap7.snap7exceptions.Snap7Exception as e:
    cpuinfo="ERR:{}".format(e)

  try:
    cpustate=c.get_cpu_state()
  except snap7.snap7exceptions.Snap7Exception as e:
    cpustate="ERR:{}".format(e)

  try:
    cpuordercode=c.get_order_code()
  except snap7.snap7exceptions.Snap7Exception as e:
    cpuordercode="ERR:{}".format(e)

  try:
    cpuprotection=c.get_protection()
  except snap7.snap7exceptions.Snap7Exception as e:
    cpuprotection="ERR:{}".format(e)

  try:
    c.set_session_password("S7upid")
    # Test a fake upload from the AG
    c.upload('')
    cpupassword='YES/NOCHECK'
  except snap7.snap7exceptions.Snap7Exception as e:
    if e.message.find('function refused by CPU') != -1:
      cpupassword='unlikely (function refused by CPU)'
    elif e.message.find('not authorized for current protection level') != -1:
      # snap7.snap7exceptions.Snap7Exception: CPU : Function not authorized for current protection level
      cpupassword='YES'
    else:
      cpupassword="maybe: '{}'".format(e.message)
  if cpupassword == None:
    cpupassword='YES'
  print("[{}] CPUState: '{}', ASName: '{}', Copyright: '{}', ModuleName: '{}', ModuleTypeName: '{}', SerialNumber: '{}', OrderCode: '{}', Protection: '{}', PassSupported: '{}'".format(_target, cpustate, cpuinfo.ASName, cpuinfo.Copyright, cpuinfo.ModuleName, cpuinfo.ModuleTypeName, cpuinfo.SerialNumber, cpuordercode, cpuprotection, cpupassword))
  # Protection level : https://cache.industry.siemens.com/dl/files/604/44240604/att_67003/v1/s7sfc_en-EN.pdf
  # See '4.6 Activating Write-protection with SFC 109 "PROTECT"'
  # 1 : All programming device functions are permitted 
  # 2 : Download of objects from the CPU to the programming device is permitted, i.e. only read-only programming device functions are permitted. 
  #     The functions for process control, process monitoring and process communication are permitted. 
  #     All informational functions are permitted. 
  # Set to protection level 2 : the program and the configuration of the CPU cannot be changed. The program in the CPU can be read with the programming device.

i=0
(nbip, ips) = expand_ips(sys.argv[1:])

for ip in ips:
  i+=1
  os.write(2, '{}/{} [{}%]   {}      \r'.format(i, nbip, 100*i/nbip, ip))
  scan("{}".format(ip))
print("                                                                                                  ")
