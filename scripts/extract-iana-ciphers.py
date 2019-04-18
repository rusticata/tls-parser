#!/usr/bin/python

import urllib2
from BeautifulSoup import BeautifulSoup, ResultSet
file = urllib2.urlopen('http://www.iana.org/assignments/tls-parameters/tls-parameters.xml')
data = file.read()
with open('tls-parameters.xml', 'wb') as myFile:
    myFile.write(data)
file.close()

dom = BeautifulSoup(data)

#ciphersuites=dom.findAll ("registry")[4]
ciphersuites=dom.findAll (id="tls-parameters-4")
if isinstance(ciphersuites,ResultSet):
    ciphersuites = ciphersuites.pop()

for i in ciphersuites.findAll ("record"):
  value = "".join(i.value.contents)
  desc = "".join (i.description.contents)
  
  ignore_keywords = [
          "Unassigned",
          "Reserved",
          ]
  f = filter(desc.startswith,ignore_keywords)
  
  if len(f) > 0:
    continue
  
  if desc == "TLS_EMPTY_RENEGOTIATION_INFO_SCSV":
    continue
  elif desc == "TLS_FALLBACK_SCSV":
    continue
  
  rfc = "NONE"
  if i.xref:
    rfc_tmp = filter (lambda (var,val) : var == "data", i.xref.attrs)
    if len (rfc_tmp) > 0:
      # rfc = rfc_tmp[0][1][3:7]
      rfc = rfc_tmp[0][1]

  real_value = "".join (map (lambda x : "%2.2x" % (int (x, 16)), value.split (",")))

  minver = 0x0300
  maxver = 0xffff
  
  if rfc == "rfc8446":
    kxau = ["TLS13"]
    encmac = desc[4:] # skip "TLS_"
  elif rfc == "draft-camwinget-tls-ts13-macciphersuites":
    kxau = ["TLS13"]
    encmac = "NULL_" + desc.split("_")[1] # forge string like NULL_SHA256
  else:
    (_kxau, encmac) = desc.split("_WITH_")
    kxau = _kxau.split ("_")[1:]
  export = 0
  if kxau[-1] == "EXPORT":
    export = 1
    maxver = 0x302
    kxau = kxau[:-1]
  if len (kxau) == 1:
    kx = kxau[0]
    au = kxau[0]
  elif kxau[0] == "SRP":
    kx = "_".join (kxau[0:1])
    au = kx
    if len (kxau) > 2:
      au += "+" + "_".join (kxau[2:])
  elif kxau[0] == "GOSTR341112":
    # unsupported suites from https://datatracker.ietf.org/doc/draft-smyshlyaev-tls12-gost-suites/
    continue
  else:
    kx, au = kxau
  if au == "anon":
    au = "NULL"
  
  _encmac = encmac.split ("_")
  hashfun = _encmac [-1]
  _encstr = "_".join (_encmac [:-1])
  _enc = _encmac [:-1] 
 
  if _encstr == "DES40_CBC":
    enc = "DES"
    encmode = "CBC"
    encsize = 40
  elif len (_enc) == 3 and _enc[1] == "CBC" and _enc[2] == "40":
    enc = _enc[0]
    encmode = "CBC"
    encsize = 40
  elif _encstr == "DES_CBC":
    enc = "DES"
    encmode = "CBC"
    encsize = 56
  elif _encstr == "IDEA_CBC":
    enc = "IDEA"
    encmode = "CBC"
    encsize = 128
  elif _encstr == "3DES_EDE_CBC":
    enc = "3DES"
    encmode = "CBC"
    encsize = 168
  elif _encstr == "NULL":
    enc = "NULL"
    encmode = ""
    encsize = 0
  elif _encstr == "SEED_CBC":
    enc = "SEED"
    encmode = "CBC"
    encsize = 128
  elif _encstr == "CHACHA20_POLY1305":
    enc = "CHACHA20_POLY1305"
    encmode = "CBC"
    encsize = 256
  elif len (_enc) == 2:
    enc = _enc[0]
    encmode = ""
    encsize = int (_enc[1])
  else:
    enc = _enc[0]
    encmode = _enc[2]
    encsize = int (_enc[1])

  prf = "DEFAULT"
  prfsize = 0

  # fix crap from recent changes
  if hashfun == "8":
    hashfun = "_".join([encmode,hashfun])
    encmode = ""
  
  if hashfun == "NULL":
    mac = "NULL"
    macsize = 0
  elif hashfun == "MD5":
    mac = "HMAC-MD5"
    macsize = 128
  elif hashfun == "SHA":
    mac = "HMAC-SHA1"
    macsize = 160
  elif hashfun == "SHA256":
    mac = "HMAC-SHA256"
    macsize = 256
    prf = "SHA256"
    prfsize = 256
    minver = 0x303
  elif hashfun == "SHA384":
    mac = "HMAC-SHA384"
    macsize = 384
    prf = "SHA384"
    prfsize = 384
    minver = 0x303
  elif hashfun == "CCM":
    #print encmode
    #mac = "CCM"
    #macsize = 0
    minver = 0x303
    encmode = "CCM"
  elif hashfun == "CCM_8":
    #print encmode
    #mac = "CCM_8"
    #macsize = 0
    minver = 0x303
    encmode = "CCM"
  else:
    print desc
    print encmac
    print hashfun
    raise "Unsupported."
  
  if encmode == "GCM" or encmode == "CCM":
    mac = "AEAD"
    macsize = encsize
    minver = 0x303
  if _encstr == "CHACHA20_POLY1305":
    mac = "AEAD"
    macsize = encsize
    minver = 0x303
    
  print "%s:%s:%s:%s:%s:%s:%d:%s:%d:%s:%d:%s:%d:%4.4x:%4.4x" % (real_value, desc, kx, au, enc, encmode, encsize, mac, macsize, prf, prfsize, rfc, export, minver, maxver)
