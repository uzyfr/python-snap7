import snap7
import os
import sys
import time

snap7.common.logger.disabled=True

def expand_ips(_ips):
  s=set()
  for i in _ips:
    # Do stuff like expand '-', treat '*' or ','
    s.add(i)
  return (len(s), s)

def scan(_target):
  c=snap7.client.Client()
  try:
    c.connect(_target, 0, 0)
  except Exception as e:
    return True
  cpuinfo=c.get_cpu_info()
  cpustate=c.get_cpu_state()
  print("\nIP: {}, CPUState: '{}', ASName: '{}', Copyright: '{}', ModuleName: '{}', ModuleTypeName: '{}', SerialNumber: '{}', OrderCode: '{}', Protections: '{}'".format(_target, cpustate, cpuinfo.ASName, cpuinfo.Copyright, cpuinfo.ModuleName, cpuinfo.ModuleTypeName, cpuinfo.SerialNumber, c.get_order_code(), c.get_protection()))
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
  os.write(2, '\r{}/{} [{}%]   {}      '.format(i, nbip, 100*i/nbip, ip))
  scan("{}".format(ip))
