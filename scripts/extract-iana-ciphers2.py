#!/usr/bin/python3

import csv
import urllib.request
import sys
import re

# Where to get the TLS parameters from.
# See http://www.iana.org/assignments/tls-parameters/tls-parameters.xml.
URL = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"

def getCiphers():
    req = urllib.request.urlopen(URL)
    data = req.read().decode('utf-8')
    # f = open("tls-parameters-4.csv", "r")
    # data = f.read()

    ciphers = []
    reader = csv.DictReader(data.splitlines())
    for row in reader:
            desc = row["Description"]
            rawval = row["Value"]
            rfcs = row["Reference"]

            # Just plain TLS values for now, to keep it simple.
            if "-" in rawval or not desc.startswith("TLS"):
                continue

            rv1, rv2 = rawval.split(",")
            rv1, rv2 = int(rv1, 16), int(rv2, 16)

            val = "%02x%02x" % (rv1, rv2)
            ciphers.append((val, desc, rfcs))

    # Manually adding ciphers from https://datatracker.ietf.org/doc/html/draft-ietf-tls-56-bit-ciphersuites-01
    ciphers.append(("0062", "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", "draft-ietf-tls-56-bit-ciphersuites-01"))
    ciphers.append(("0064", "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", "draft-ietf-tls-56-bit-ciphersuites-01"))
    ciphers.append(("0063", "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", "draft-ietf-tls-56-bit-ciphersuites-01"))
    ciphers.append(("0065", "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", "draft-ietf-tls-56-bit-ciphersuites-01"))
    ciphers.append(("0066", "TLS_DHE_DSS_WITH_RC4_128_SHA", "draft-ietf-tls-56-bit-ciphersuites-01"))

    # Unsure which RFC these are coming from
    ciphers.append(("0060", "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", "unknown"))
    ciphers.append(("0061", "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", "unknown"))

    return ciphers

re_tls_with = re.compile('^TLS_(\w+)_WITH_(\w+)_(\w+)$')

MAP_KX = {
        'NULL': ['NULL', 'NULL'],
        'DH_anon': ['DH', 'NULL'],
        'DH_anon_EXPORT': ['DH', 'NULL'],
        'DH_DSS': ['DH', 'DSS'],
        'DH_DSS_EXPORT': ['DH', 'DSS'],
        'DHE_DSS': ['DHE', 'DSS'],
        'DHE_DSS_EXPORT': ['DHE', 'DSS'],
        'DHE_DSS_EXPORT1024': ['DHE', 'DSS'],
        'RSA': ['RSA', 'RSA'],
        'RSA_EXPORT1024': ['RSA', 'RSA'],
        'DH_RSA': ['DH', 'RSA'],
        'DH_RSA_EXPORT': ['DH', 'RSA'],
        'DHE_PSK': ['DHE', 'PSK'],
        'DHE_RSA': ['DHE', 'RSA'],
        'DHE_RSA_EXPORT': ['DHE', 'RSA'],
        'ECCPWD': ['ECCPWD', 'ECCPWD'],
        'ECDH_ECDSA': ['ECDH', 'ECDSA'],
        'ECDH_anon': ['ECDH', 'NULL'],
        'ECDH_RSA': ['ECDH', 'RSA'],
        'ECDHE_ECDSA': ['ECDHE', 'ECDSA'],
        'ECDHE_PSK': ['ECDHE', 'PSK'],
        'ECDHE_RSA': ['ECDHE', 'RSA'],
        'PSK': ['PSK', 'PSK'],
        'PSK_DHE': ['PSK', 'DHE'],
        'KRB5': ['KRB5', 'KRB5'],
        'KRB5_EXPORT': ['KRB5', 'KRB5'],
        'RSA_EXPORT': ['RSA', 'RSA'],
        'RSA_PSK': ['RSA', 'PSK'],
        'SRP_SHA': ['SRP', 'SRP'],
        'SRP_SHA_DSS': ['SRP', 'SRP+DSS'],
        'SRP_SHA_RSA': ['SRP', 'SRP+RSA'],
        'TLS13': ['TLS13', 'TLS13'],
        }

MAP_ENC = {
        'NULL': ['NULL', '', 0],
        'NULL_SHA256': ['NULL', '', 0],
        '3DES_EDE_CBC': ['3DES', 'CBC', 168],
        'AEGIS_128L': ['AEGIS', 'NULL', 128],
        'AEGIS_128X2': ['AEGIS', 'NULL', 128],
        'AEGIS_256': ['AEGIS', 'NULL', 256],
        'AEGIS_256X2': ['AEGIS', 'NULL', 256],
        'AES_128_CBC': ['AES', 'CBC', 128],
        'AES_256_CBC': ['AES', 'CBC', 256],
        'AES_128_CCM': ['AES', 'CCM', 128],
        'AES_128_CCM_8': ['AES', 'CCM', 128],
        'AES_256_CCM': ['AES', 'CCM', 256],
        'AES_256_CCM_8': ['AES', 'CCM', 256],
        'AES_128_GCM': ['AES', 'GCM', 128],
        'AES_256_GCM': ['AES', 'GCM', 256],
        'ARIA_128_CBC': ['ARIA', 'CBC', 128],
        'ARIA_256_CBC': ['ARIA', 'CBC', 256],
        'ARIA_128_GCM': ['ARIA', 'GCM', 128],
        'ARIA_256_GCM': ['ARIA', 'GCM', 256],
        'CAMELLIA_128_CBC': ['CAMELLIA', 'CBC', 128],
        'CAMELLIA_256_CBC': ['CAMELLIA', 'CBC', 256],
        'CAMELLIA_128_GCM': ['CAMELLIA', 'GCM', 128],
        'CAMELLIA_256_GCM': ['CAMELLIA', 'GCM', 256],
        'CHACHA20_POLY1305': ['CHACHA20_POLY1305', '', 128],
        'DES_CBC': ['DES', 'CBC', 56],
        'DES_CBC_40': ['DES', 'CBC', 40],
        'DES40_CBC': ['DES', 'CBC', 40],
        'IDEA_CBC': ['IDEA', 'CBC', 128],
        'RC2_CBC_40': ['RC2', 'CBC', 40],
        'RC2_CBC_56': ['RC2', 'CBC', 56],
        'RC4_40': ['RC4', '', 40],
        'RC4_56': ['RC4', '', 56],
        'RC4_128': ['RC4', '', 128],
        'SEED_CBC': ['SEED', 'CBC', 128],
        'SM4_CCM': ['SM4', 'CCM', 128],
        'SM4_GCM': ['SM4', 'GCM', 128],
        }

MAP_MAC = {
        'NULL': ['NULL', 0, 'DEFAULT', 0],
        'MD5': ['HMAC-MD5', 128, 'DEFAULT', 0],
        'SHA': ['HMAC-SHA1', 160, 'DEFAULT', 0],
        'SHA256': ['HMAC-SHA256', 256, 'SHA256', 256],
        'SHA384': ['HMAC-SHA384', 384, 'SHA384', 384],
        'SHA512': ['HMAC-SHA512', 512, 'SHA512', 512],
        'SM3': ['SM3', 256, 'SM3', 256],
        }

def extract_ciphersuite_info(desc, rfcs):
    params = dict()
    if desc == "TLS_SHA256_SHA256":
        desc = "TLS_TLS13_WITH_NULL_SHA256"
    if desc == "TLS_SHA384_SHA384":
        desc = "TLS_TLS13_WITH_NULL_SHA384"
    if not "_WITH_" in desc:
        if desc.startswith("TLS_AES") or desc.startswith("TLS_CHACHA20") or desc.startswith("TLS_AEGIS"):
            # XXX special case: TLS 1.3: TLS_AES_128_GCM_SHA256 etc.
            desc = "TLS_TLS13_WITH_" + desc[4:]
        else:
            raise Exception("Unsupported ciphersuite %s" % desc)
    (_kxau, encmac) = desc.split("_WITH_")
    m = re_tls_with.match(desc)
    if m:
        orig_kx = params['kx'] = m.group(1)
        orig_au = params['au'] = m.group(1)
        orig_enc = params['enc'] = m.group(2)
        orig_mac = params['mac'] = m.group(3)
        # raise(Exception("Found {}".format(params)))
    else:
        raise Exception("Unsupported ciphersuite %s" % desc)
    #
    # normalize
    #
    if desc.endswith("CCM") or desc.endswith("CCM_8"):
        # special case: TLS_RSA_WITH_AES_128_CCM (RFC6655)
        orig_enc = orig_enc + "_" + orig_mac
        orig_mac = 'NULL'
    p = re.compile("\[|\]")
    m = p.split(rfcs)
    rfcs = [s.lower() for s in filter(lambda s: len(s) > 0, m)]
    #
    # get parameters
    #
    (kx, au) = MAP_KX[orig_kx]
    enc_long = params['enc']
    (enc, encmode, encsize) = MAP_ENC[orig_enc]
    (mac, macsize, prf, prfsize) = MAP_MAC[orig_mac]
    #
    # fixups
    #
    if encmode == "CCM" or encmode == "GCM":
        mac = "AEAD"
        macsize = encsize
    if enc == "CHACHA20_POLY1305":
        mac = "AEAD"
        macsize = encsize
    # XXX (not used yet)
    minver = 0x0300
    maxver = 0xffff
    # end
    params['kx'] = kx
    params['au'] = au
    params['enc'] = enc
    params['encmode'] = encmode
    params['encsize'] = encsize
    params['mac'] = mac
    params['macsize'] = macsize
    params['prf'] = prf
    params['prfsize'] = prfsize
    params['rfc'] = rfcs
    params['minver'] = minver
    params['maxver'] = maxver
    # print("Found {}".format(params))
    return params

ciphers = getCiphers()
out = open(sys.argv[1], 'w')

for value, desc, rfcs in ciphers:
    # filter special values
    full_desc = desc
    if desc == "TLS_EMPTY_RENEGOTIATION_INFO_SCSV" or desc == "TLS_FALLBACK_SCSV":
        out.write("%s:%s:NULL:NULL:NULL::0:NULL:0:NULL:0:%s:0:0:0\n" %
                (value,desc,rfcs,)
                )
        continue
    elif desc.startswith("TLS_SM4"):
        # special case: draft-yang-tls-tls13-sm-suites-03
        full_desc = "TLS_TLS13_WITH_" + desc[4:]
    elif desc.startswith("TLS_GOST"):
        # XXX ignore special case: TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC (draft-smyshlyaev-tls12-gost-suites)
        continue
    elif "draft-camwinget-tls-ts13-macciphersuites" in rfcs or "RFC-camwinget-tls-ts13-macciphersuites-12" in rfcs:
        # "TLS_SHA256_SHA256" and similar
        full_desc = "TLS_TLS13_WITH_NULL_" + desc[4:-7]
    # print("%s %s %s" % (value, desc, rfcs))
    # split ciphersuite info
    cs_info = extract_ciphersuite_info(full_desc, rfcs)
    if cs_info is None:
        raise Exception("Unsupported ciphersuite %s" % desc)
    if cs_info['encsize'] == 40:
        export = 1
    else:
        export = 0
    out.write("%s:%s:%s:%s:%s:%s:%d:%s:%d:%s:%d:%s:%s:%4.4x:%4.4x\n" %
            (value,desc,
                cs_info['kx'],
                cs_info['au'],
                cs_info['enc'],
                cs_info['encmode'],
                cs_info['encsize'],
                cs_info['mac'],
                cs_info['macsize'],
                cs_info['prf'],
                cs_info['prfsize'],
                ','.join(cs_info['rfc']),
                export,
                cs_info['minver'],
                cs_info['maxver'],
                )
            )
