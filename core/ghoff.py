# simontok.apk
#WARNA
R = '\033[31m'
ww = '\033[37m'
Y = '\033[93m'
y = '\033[33m'
W = '\033[00m'
w = '\033[00m'
x = '\033[36m'
b = '\033[34m'
#BAHAN 1
import os,sys,time,zlib,random,base64,re,itertools,hashlib,binascii
from itertools import cycle
from string import lowercase, uppercase
from time import sleep
#BAHAN 2
try:
    import plib,pbar
except ImportError:
    print("%s[%s-%s] %sERROR%s: %smodule %splib %sand %spbar %sNot Installed %s!" % (R,Y,R,W,R,W,R,W,R,W,R))
    sys.exit()

str_endeop = '''

%s[1] %sEncode%s
[2] %sDecode

%s[*] %sChoice :%s ''' % (R,W,R,W,W,R,W)
l_edr = ['[+] Hash : ',\
         '[*] String : ',\
         '[*] Text to Decode : ']
e = "%s[%s*%s] %sHash   %s>>> %s" % (R,y,R,w,R,w)
q = "%s[%s*%s] %sString %s>>> %s" % (R,y,R,w,R,w)
adm_ngentod = " \033[04mHashTool\033[00m \033[31m>>>\033[00m "
def clear():
	os.system("clear")
def s():
	print " "
def md4():
	s()
	x = raw_input(q)
	m = hashlib.new("md4")
	m.update(x)
	md4 = m.hexdigest()
	print (e+md4)
	s()
def md5hash():
	print w+" "
	hash = hashlib.md5(raw_input(q)).hexdigest()
	print(e+hash)
	s()
def sha1hash():
	print w+" "
	hash = hashlib.sha1(raw_input(q)).hexdigest()
	print(e+hash)
	s()
def sha224hash():
	print w+""
	hash = hashlib.sha224(raw_input(q)).hexdigest()
	print(e+hash)
	s()
def sha256hash():
	print ""
	hash = hashlib.sha256(raw_input(q)).hexdigest()
	print(e+hash)
	s()
def sha384hash():
	print ""
	hash = hashlib.sha384(raw_input(q)).hexdigest()
	print(e+hash)
	s()
def sha512hash():
	print " \033[31m"
	hash = hashlib.sha512(raw_input(q)).hexdigest()
	print(e+hash)
	s()
def base64hash(i_opt):
    a = [{1:base64.b64encode, 2:base64.b64decode},\
         {1:base64.b32encode, 2:base64.b32decode},\
         {1:base64.b16encode, 2:base64.b16decode}]
    b = int(raw_input(str_endeop))
    print ''
    if (b > 2): sys.exit()
    s = raw_input(l_edr[b])
    print l_edr[0] + a[i_opt][b](s)
    print ""
def ripemd160hash():
	s()
	ls = raw_input(q)
	m = hashlib.new("ripemd160")
	m.update(ls)
	ripemd160 = m.hexdigest()
	print(e+ripemd160)
	s()
def adler32():
	print ""
	hash = raw_input(q)
	h = zlib.adler32(hash)
	adler32 = '%08X' % (h & 0xffffffff,)
	print(e+adler32)
	s()
def crc32():
	s()
	hash = raw_input(q)
	h = zlib.crc32(hash)
	crc32 = '%08X' % (h & 0xffffffff,)
	print(e+crc32)
	s()
def whirlpool():
	s()
	w = raw_input(q)
	l = hashlib.new("whirlpool")
	l.update(w)
	whirlpool = l.hexdigest()
	print(e+whirlpool)
	s()
def binary():
    a = int(raw_input(str_endeop))
    print ''
    if (a > 2): sys.exit()
    b = raw_input(l_edr[a])
    return a,b
def mysql323():
	s()
	m = raw_input(q)
	from plib.hash import mysql323
	mysql1323 = mysql323.encrypt(m)
	print(e+mysql1323)
        s()
def mysql41():
	s()
	m = raw_input(q)
	from passlib.hash import mysql41
	mysql141 = mysql41.encrypt(m)
	print (e+mysql141)
	s()
def mssql2000():
	s()
	m = raw_input(q)
	from passlib.hash import mssql2000 as m20
	mssql2000 = m20.encrypt(m)
	print (e+mssql2000)
	s()
def mssql2005():
	s()
	m = raw_input(q)
	from passlib.hash import mssql2005 as m25
	mssql2005 = m25.encrypt(m)
	print (e+mssql2005)
	s()
def des():
	s()
	m = raw_input(q)
	from passlib.hash import des_crypt
	des = des_crypt.encrypt(m)
	print (e+des)
	s()
def bsdicrypt():
	s()
	m = raw_input(q)
	from passlib.hash import bsdi_crypt
	bsdi = bsdi_crypt.encrypt(m)
	print (e+bsdi)
	s()
def bigcrypt():
	s()
	m = raw_input(q)
	from passlib.hash import bigcrypt
	big = bigcrypt.encrypt(m)
	print (e+big)
	s()
def crypt16():
	s()
	m = raw_input(q)
	from passlib.hash import crypt16
	crypt16 = crypt16.encrypt(m)
	print (e+crypt16)
	s()
def md5crypt():
	s()
	m = raw_input(q)
	from passlib.hash import md5_crypt as mc
	md5_crypt = mc.encrypt(m)
	print (e+md5_crypt)
	s()
def sha1crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sha1_crypt as mc
	sha1_crypt = mc.encrypt(m)
	print (e+sha1_crypt)
	s()
def sha256crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sha256_crypt as mc
	sha256_crypt = mc.encrypt(m)
	print (e+sha256_crypt)
	s()
def sha512crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sha512_crypt as mc
	sha512_crypt = mc.encrypt(m)
	print (e+sha512_crypt)
	s()
def sunmd5crypt():
	s()
	m = raw_input(q)
	from passlib.hash import sun_md5_crypt as mc
	sun_md5_crypt = mc.encrypt(m)
	print (e+sun_md5_crypt)
	s()
def apachemd5crypt():
	s()
	m = raw_input(q)
	from passlib.hash import apr_md5_crypt as mc
	apr_md5_crypt = mc.encrypt(m)
	print (e+apr_md5_crypt)
	s()
def phpass():
	s()
	m = raw_input(q)
	from passlib.hash import phpass as mc
	phpass = mc.encrypt(m)
	print (e+phpass)
	s()
def cryptacularspbdf2():
	s()
	m = raw_input(q)
	from passlib.hash import cta_pbkdf2_sha1 as mc
	cta_pbkdf2_sha1 = mc.encrypt(m)
	print (e+cta_pbkdf2_sha1)
	s()
def dwinepbdf2():
	s()
	m = raw_input(q)
	from passlib.hash import dlitz_pbkdf2_sha1 as mc
	dlitz_pbkdf2_sha1 = mc.encrypt(m)
	print (e+dlitz_pbkdf2_sha1)
	s()
def djangosha1():
	s()
	m = raw_input(q)
	from passlib.hash import django_pbkdf2_sha1 as m25
	django_sha1 = m25.encrypt(m)
	print (e+django_sha1)
	s()
def djangosha256():
	s()
	m = raw_input(q)
	from passlib.hash import django_pbkdf2_sha256 as m25
	django_sha256 = m25.encrypt(m)
	print (e+django_sha256)
	s()
def gruppbkdf2sha512():
	s()
	m = raw_input(q)
	from passlib.hash import grub_pbkdf2_sha512 as m25
	grup_pbkdf2_sha512 = m25.encrypt(m)
	print (e+grup_pbkdf2_sha512)
	s()
def atlassianspbkdf2():
	s()
	m = raw_inpur(q)
	from passlib.hash import cta_pbkdf2_sha1 as mc
	atl_pbkdf2_sha1 = mc.encrypt(m)
	print (e+atl_pbkdf2_sha1)
	s()
def scram():
	s()
	m = raw_input(q)
	from passlib.hash import scram as mc
	scram = mc.encrypt(m)
	print (e+scram)
	s()
def bsdnthash():
	s()
	m = raw_input(q)
	from passlib.hash import bsd_nthash as mc
	bsd_nthash = mc.encrypt(m)
	print (e+bsd_nthash)
	s()
def oracle11():
	s()
	m = raw_input(q)
	from passlib.hash import oracle11 as m25
	oracle11 = m25.encrypt(m)
	print (e+oracle11)
	s()
def lanmanager():
	s()
	m = raw_input(q)
	from passlib.hash import lmhash as m25
	lmhash = m25.encrypt(m)
	print (e+lmhash)
	s()
def nthash():
	s()
	m = raw_input(q)
	from passlib.hash import nthash as m25
	nthash = m25.encrypt(m)
	print(e+nthash)
	s()
def ciscotype7():
	s()
	m = raw_input(q)
	from passlib.hash import cisco_type7 as m25
	cisco = m25.encrypt(m)
	print(e+cisco)
	s()
def fhsp():
	s()
	m = raw_input(q)
	from passlib.hash import fshp as m25
	fhsp = m25.encrypt(m)
	print(e+fhsp)
	s()
def ciscopix():
	s()
	m = raw_input(q)
	from passlib.hash import cisco_pix as m25
	ciscop = m25.encrypt(m)
	print(e+ciscop)
	s()
def ciscoasa():
	s()
	m = raw_input(q)
	from passlib.hash import cisco_asa as m25
	ciscoa = m25.encrypt(m)
	print(e+ciscoa)
	s()
def descrypt():
	s()
	m = raw_input(q)
	from passlib.hash import des_crypt as m25
	desc = m25.encrypt(m)
	print(e+desc)
	s()
def djangosaltedsha1():
	s()
	m = raw_input(q)
	from passlib.hash import django_salted_sha1 as m25
	dj1 = m25.encrypt(m)
	print(e+dj1)
	s()
def djangosaltedmd5():
	s()
	m = raw_input(q)
	from passlib.hash import django_salted_md5 as m25
	dj2 = m25.encrypt(m)
	print(e+dj2)
	s()
def djangodisabled():
	s()
	m = raw_input(q)
	from passlib.hash import django_disabled as m25
	dj3 = m25.encrypt(m)
	print(e+dj3)
	s()
def djangodescrypt():
	s()
	m = raw_input(q)
	from passlib.hash import django_des_crypt as m25
	dj4 = m25.encrypt(m)
	print(e+dj4)
	s()
def ldapmd5():
	s()
	m = raw_input(q)
	from passlib.hash import ldap_md5 as m25
	l1 = m25.encrypt(m)
	print(e+l1)
	s()
def ldapsha1():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_sha1 as m25
	l2 = m25.encrypt(m)
	print(e+l2)
	s()
def ldapsaltedmd5():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_salted_md5 as m25
	l3 = m25.encrypt(m)
	print(e+l3)
	s()
def ldalsaltedsha1():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_salted_sha1 as m25
	l4 = m25.encrypt(m)
	print(e+l4)
	s()
def roundupplaintext():
	s()
        m = raw_input(q)
        from passlib.hash import roundup_plaintext as m25
	rp = m25.encrypt(m)
	print(e+rp)
	s()
def ldaphexmd5():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_hex_md5 as m25
	lhm = m25.encrypt(m)
	print(e+lhm)
	s()
def ldaphexsha1():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_hex_sha1 as m25
	lhs = m25.encrypt(m)
	print(e+lhs)
	s()
def lmhash():
	s()
        m = raw_input(q)
        from passlib.hash import lmhash as m25
	lh = m25.encrypt(m)
	print(e+lh)
	s()
def bsdnthash():
	s()
        m = raw_input(q)
        from passlib.hash import bsd_nthash as m25
	bn = m25.encrypt(m)
	print(e+bn)
	s()
def ldapbsdicrypt():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_bsdi_crypt as m25
	m01 = m25.encrypt(m)
        print(e+m01)
        s()
def ldapdescrypt():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_des_crypt as m25
	m02 = m25.encrypt(m)
        print(e+m02)
        s()
def ldapmd5crypt():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_md5_crypt as m25
	m03 = m25.encrypt(m)
        print(e+03)
        s()
def ldapsha256crypt():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_sha256_crypt as m25
	m04 = m25.encrypt(m)
        print(e+m04)
        s()
def ldapsha512crypt():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_sha512_crypt as m25
	m05 = m25.encrypt(m)
	print(e+m05)
	s()
def ldapsha1crypt():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_sha1_crypt as m25
	m07 = m25.encrypt(m)
        print(e+07)
        s()
def ldappbkdf2sha1():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_pbkdf2_sha1 as m25
	m08 = m25.encrypt(m)
        print(e+m08)
        s()
def ldappbkdf2sha256():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_pbkdf2_sha256 as m25
	m09 = m25.encrypt(m)
        print(e+m09)
        s()
def ldappbkdf2sha512():
	s()
        m = raw_input(q)
        from passlib.hash import ldap_pbkdf2_sha512 as m25
	qlq = m25.encrypt(m)
        print(e+qlq)
        s()
def pbkdf2sha1():
	s()
        m = raw_input(q)
        from passlib.hash import pbkdf2_sha1 as m25
	ps11 = m25.encrypt(m)
        print(e+ps11)
        s()
def pbkdf2sha256():
	s()
        m = raw_input(q)
        from passlib.hash import pbkdf2_sha256 as m25
	alks = m25.encrypt(m)
        print(e+alks)
        s()
def pbkdf2sha512():
	s()
        m = raw_input(q)
        from passlib.hash import pbkdf2_sha512 as m25
	mmm = m25.encrypt(m)
        print(e+mmm)
        s()
def djangopbkdf2sha1():
	s()
        m = raw_input(q)
        from passlib.hash import django_pbkdf2_sha1 as m25
	mmmm = m25.encrypt(m)
        print(e+mmmm)
        s()
def djangopbkdf2sha256():
	s()
        m = raw_input(q)
        from passlib.hash import django_pbkdf2_sha256 as m25
	mmmmm = m25.encrypt(m)
        print(e+mmmmm)
        s()


def all():
	print ""
	hash = raw_input(q)
	clear()
	m4 = hashlib.new("md4")
	m4.update(hash)
	md4 = m4.hexdigest()
	md5 = hashlib.md5(hash.encode()).hexdigest()
	sha1 = hashlib.sha1(hash.encode()).hexdigest()
	sha224 = hashlib.sha224(hash.encode()).hexdigest()
	sha384 = hashlib.sha384(hash.encode()).hexdigest()
	sha512 = hashlib.sha512(hash.encode()).hexdigest()
	sha256 = hashlib.sha256(hash.encode()).hexdigest()
        m = hashlib.new("ripemd160")
        m.update(hash)
        ripemd160 = m.hexdigest()
	h = zlib.adler32(hash)
        adler32 = '%08X' % (h & 0xffffffff,)
	ss = zlib.crc32(hash)
        crc32 = '%08X' % (ss & 0xffffffff,)
        l = hashlib.new("whirlpool")
        l.update(hash)
        whirlpool = l.hexdigest()
        print "%s[%s01%s] %sMD4                %s: %s%s" % (R,b,R,x,R,W,md4)
        print "%s[%s02%s] %sMD5                %s: %s%s" % (R,b,R,x,R,W,md5)
        print "%s[%s03%s] %sSHA1               %s: %s%s" % (R,b,R,x,R,W,sha1)
        print "%s[%s04%s] %sSHA224             %s: %s%s" % (R,b,R,x,R,W,sha224)
        print "%s[%s05%s] %sSHA256             %s: %s%s" % (R,b,R,x,R,W,sha256)
	print "%s[%s06%s] %sSHA384             %s: %s%s" % (R,b,R,x,R,W,sha384)
        print "%s[%s07%s] %sSHA512             %s: %s%s" % (R,b,R,x,R,W,sha512)
        print "%s[%s08%s] %sADLER32            %s: %s%s" % (R,b,R,x,R,w,adler32.lower())
        print "%s[%s09%s] %sCRC32              %s: %s%s" % (R,b,R,x,R,w,crc32.lower())
        print "%s[%s10%s] %sRipemd160          %s: %s%s" % (R,b,R,x,R,W,ripemd160)
        print "%s[%s11%s] %sWHIRLPOOL          %s: %s%s" % (R,b,R,x,R,W,whirlpool)
	from plib.hash import mysql323
        mysql1323 = mysql323.encrypt(hash)
	print "%s[%s12%s] %sMYSQL323           %s: %s%s" % (R,b,R,x,R,W,mysql1323)
        from plib.hash import mysql41
        mysql141 = mysql41.encrypt(hash)
	print "%s[%s13%s] %sMYSQL41            %s: %s%s" % (R,b,R,x,R,W,mysql141)
	from plib.hash import mssql2000 as m20
        mssql2000 = m20.encrypt(hash)
	print "%s[%s14%s] %sMSSQL 2000         %s: %s%s" % (R,b,R,x,R,W,mssql2000)
	from plib.hash import mssql2005 as m25
        mssql2005 = m25.encrypt(hash)
	print "%s[%s15%s] %sMSSQL 2005         %s: %s%s" % (R,b,R,x,R,W,mssql2005)
	from plib.hash import des_crypt
        des = des_crypt.encrypt(hash)
	print "%s[%s16%s] %sDES                %s: %s%s" % (R,b,R,x,R,W,des)
	from plib.hash import bsdi_crypt
        bsdi = bsdi_crypt.encrypt(hash)
	print "%s[%s17%s] %sBSDI Crypt         %s: %s%s" % (R,b,R,x,R,W,bsdi)
	from plib.hash import bigcrypt
        big = bigcrypt.encrypt(hash)
	print "%s[%s18%s] %sBig Crypt          %s: %s%s" % (R,b,R,x,R,W,big)
	from plib.hash import crypt16
	crypt16 = crypt16.encrypt(hash)
	print "%s[%s19%s] %sCrypt 16           %s: %s%s" % (R,b,R,x,R,W,crypt16)
	from plib.hash import md5_crypt as mc
        md5_crypt = mc.encrypt(hash)
	print "%s[%s20%s] %sMD5 Crypt          %s: %s%s" % (R,b,R,x,R,W,md5_crypt)
	from plib.hash import sha1_crypt as mc
        sha1_crypt = mc.encrypt(hash)
	print "%s[%s21%s] %sSHA1 Crypt         %s: %s%s" % (R,b,R,x,R,W,sha1_crypt)
	from plib.hash import sha256_crypt as mc
        sha256_crypt = mc.encrypt(hash)
	print "%s[%s22%s] %sSHA256 Crypt       %s: %s%s" % (R,b,R,x,R,W,sha256_crypt)
        from plib.hash import sha512_crypt as mc
        sha512_crypt = mc.encrypt(hash)
        print "%s[%s23%s] %sSHA512 Crypt       %s: %s%s" % (R,b,R,x,R,W,sha512_crypt)
	from plib.hash import sun_md5_crypt as mc
        sun_md5_crypt = mc.encrypt(hash)
        print "%s[%s24%s] %sSun MD5 Crypt      %s: %s%s" % (R,b,R,x,R,W,sun_md5_crypt)
	from plib.hash import apr_md5_crypt as mc
        apr_md5_crypt = mc.encrypt(hash)
        print "%s[%s25%s] %sApr MD5 Crypt      %s: %s%s" % (R,b,R,x,R,W,apr_md5_crypt)
	from plib.hash import phpass as mc
        phpass = mc.encrypt(hash)
        print "%s[%s26%s] %sPHPASS             %s: %s%s" % (R,b,R,x,R,W,phpass)
	from plib.hash import cta_pbkdf2_sha1 as mc
        cta_pbkdf2_sha1 = mc.encrypt(hash)
        print "%s[%s27%s] %sCTA PBKDF2 SHA1    %s: %s%s" % (R,b,R,x,R,W,cta_pbkdf2_sha1)
	from plib.hash import dlitz_pbkdf2_sha1 as mc
        dlitz_pbkdf2_sha1 = mc.encrypt(hash)
        print "%s[%s28%s] %sDLITZ PBKDF2 SHA1  %s: %s%s" % (R,b,R,x,R,W,dlitz_pbkdf2_sha1)
	from plib.hash import django_pbkdf2_sha1 as m25
        django_sha1 = m25.encrypt(hash)
	print "%s[%s29%s] %sDjango SHA1        %s: %s%s" % (R,b,R,x,R,W,django_sha1)
	from plib.hash import django_pbkdf2_sha256 as m25
        django_sha256 = m25.encrypt(hash)
        print "%s[%s30%s] %sDjango SHA256      %s: %s%s" % (R,b,R,x,R,W,django_sha256)
	from plib.hash import grub_pbkdf2_sha512 as m25
        grup_pbkdf2_sha512 = m25.encrypt(hash)
	print "%s[%s31%s] %sGrup PBKDF2 SHA512 %s: %s%s" %(R,b,R,x,R,W,grup_pbkdf2_sha512)
	from passlib.hash import cta_pbkdf2_sha1 as mc
        atl_pbkdf2_sha1 = mc.encrypt(hash)
	print "%s[%s32%s] %sAtlassians PBKDF2  %s: %s%s" %(R,b,R,x,R,W,atl_pbkdf2_sha1)
	from passlib.hash import scram as mc
        scram = mc.encrypt(hash)
	print "%s[%s33%s] %sSCRAM              %s: %s%s" %(R,b,R,x,R,W,scram)
	from passlib.hash import bsd_nthash as mc
        bsd_nthash = mc.encrypt(hash)
	print "%s[%s34%s] %sBSD nthash         %s: %s%s" %(R,b,R,x,R,W,bsd_nthash)
	from passlib.hash import oracle11 as m25
        oracle11 = m25.encrypt(hash)
	print "%s[%s35%s] %sORACLE11           %s: %s%s" %(R,b,R,x,R,W,oracle11)
	from passlib.hash import lmhash as m25
        lmhash = m25.encrypt(hash)
	print "%s[%s36%s] %sLanManager         %s: %s%s" %(R,b,R,x,R,W,lmhash)
	from passlib.hash import nthash as m25
        nthash = m25.encrypt(hash)
	print "%s[%s37%s] %sWindows NThash     %s: %s%s" %(R,b,R,x,R,W,nthash)
	from passlib.hash import cisco_type7 as m25
        cisco = m25.encrypt(hash)
	print "%s[%s38%s] %sCisco Type 7       %s: %s%s" %(R,b,R,x,R,W,cisco)
	from passlib.hash import fshp as m25
        fhsp = m25.encrypt(hash)
	print "%s[%s39%s] %sFHSP               %s: %s%s" %(R,b,R,x,R,W,fhsp)
	from passlib.hash import cisco_asa as m25
	qq = m25.encrypt(hash)
	print "%s[%s40%s] %sCisco ASA          %s: %s%s" %(R,b,R,x,R,W,qq)
	from passlib.hash import cisco_pix as m25
        wq = m25.encrypt(hash)
	print "%s[%s41%s] %sCisco PIX          %s: %s%s" %(R,b,R,x,R,W,wq)
	from passlib.hash import des_crypt as m25
        ee = m25.encrypt(hash)
	print "%s[%s42%s] %sDES Crypt          %s: %s%s" %(R,b,R,x,R,W,ee)
	from passlib.hash import django_salted_md5 as m25
        rr = m25.encrypt(hash)
	print "%s[%s43%s] %sDjango Salted MD5  %s: %s%s" %(R,b,R,x,R,W,rr)
	from passlib.hash import django_salted_sha1 as m25
        tt = m25.encrypt(hash)
	print "%s[%s44%s] %sDjango Salted SHA1 %s: %s%s" %(R,b,R,x,R,W,tt)
	from passlib.hash import django_disabled as m25
        yy = m25.encrypt(hash)
	print "%s[%s45%s] %sDjango Disabled    %s: %s%s" %(R,b,R,x,R,W,yy)
	from passlib.hash import django_des_crypt as m25
        uu = m25.encrypt(hash)
	print "%s[%s46%s] %sDjango DES Crypt   %s: %s%s" %(R,b,R,x,R,W,uu)
	from passlib.hash import ldap_md5 as m25
        ii = m25.encrypt(hash)
	print "%s[%s47%s] %sLdap MD5           %s: %s%s" %(R,b,R,x,R,W,ii)
	from passlib.hash import ldap_sha1 as m25
        oo = m25.encrypt(hash)
	print "%s[%s48%s] %sLdap SHA1          %s: %s%s" %(R,b,R,x,R,W,oo)
	from passlib.hash import ldap_salted_md5 as m25
        pp = m25.encrypt(hash)
	print "%s[%s49%s] %sLdap Salted MD5    %s: %s%s" %(R,b,R,x,R,W,pp)
	from passlib.hash import ldap_salted_sha1 as m25
        aa = m25.encrypt(hash)
	print "%s[%s50%s] %sLdap Salted SHA1   %s: %s%s" %(R,b,R,x,R,W,aa)
	from passlib.hash import roundup_plaintext as m25
        lss = m25.encrypt(hash)
	print "%s[%s51%s] %sRoundup Plaintext  %s: %s%s" %(R,b,R,x,R,W,lss)
	from passlib.hash import ldap_hex_md5 as m25
        dd = m25.encrypt(hash)
	print "%s[%s52%s] %sLdap Hex MD5       %s: %s%s" %(R,b,R,x,R,W,dd)
	from passlib.hash import ldap_hex_sha1 as m25
        ff = m25.encrypt(hash)
	print "%s[%s53%s] %sLdap Hex SHA1      %s: %s%s" %(R,b,R,x,R,W,ff)
	from passlib.hash import lmhash as m25
        gg = m25.encrypt(hash)
	print "%s[%s54%s] %sLMhash             %s: %s%s" %(R,b,R,x,R,W,gg)
	from passlib.hash import bsd_nthash as m25
        hh = m25.encrypt(hash)
	print "%s[%s55%s] %sWindows BSD NThash %s: %s%s" %(R,b,R,x,R,W,hh)
	from passlib.hash import ldap_bsdi_crypt as m25
	meko1 = m25.encrypt(hash)
	print "%s[%s56%s] %sLdap BSDI Crypt    %s: %s%s" %(R,b,R,x,R,W,meko1)
	from passlib.hash import ldap_des_crypt as m25
	meko2 = m25.encrypt(hash)
	print "%s[%s57%s] %sLdap DES Crypt     %s: %s%s" %(R,b,R,x,R,W,meko2)
	from passlib.hash import ldap_md5_crypt as m25
	meko3 = m25.encrypt(hash)
	print "%s[%s58%s] %sLdap MD5 Crypt     %s: %s%s" %(R,b,R,x,R,W,meko3)
	from passlib.hash import ldap_sha256_crypt as m25
	meko4 = m25.encrypt(hash)
	print "%s[%s59%s] %sLdap SHA256 Crypt  %s: %s%s" %(R,b,R,x,R,W,meko4)
	from passlib.hash import ldap_sha512_crypt as m25
	meko5 = m25.encrypt(hash)
	print "%s[%s60%s] %sLdap SHA512 Crypt  %s: %s%s" %(R,b,R,x,R,W,meko5)
	from passlib.hash import ldap_sha1_crypt as m25
	meko6 = m25.encrypt(hash)
	print "%s[%s61%s] %sLdap SHA1 Crypt    %s: %s%s" %(R,b,R,x,R,W,meko6)
	from passlib.hash import ldap_pbkdf2_sha1 as m25
	meko7 = m25.encrypt(hash)
	print "%s[%s62%s] %sLdap PBKDF2 SHA1   %s: %s%s" %(R,b,R,x,R,W,meko7)
	from passlib.hash import ldap_pbkdf2_sha256 as m25
	meko8 = m25.encrypt(hash)
	print "%s[%s63%s] %sLdap PBKDF2 SHA256 %s: %s%s" %(R,b,R,x,R,W,meko8)
	from passlib.hash import ldap_pbkdf2_sha512 as m25
	meko9 = m25.encrypt(hash)
	print "%s[%s64%s] %sLdap PBKDF2 SHA512 %s: %s%s" %(R,b,R,x,R,W,meko9)
	from passlib.hash import pbkdf2_sha1 as m25
	mek1 = m25.encrypt(hash)
	print "%s[%s65%s] %sPBKDF2 SHA1        %s: %s%s" %(R,b,R,x,R,W,mek1)
	from passlib.hash import pbkdf2_sha256 as m25
	mek2 = m25.encrypt(hash)
	print "%s[%s66%s] %sPBKDF2 SHA256      %s: %s%s" %(R,b,R,x,R,W,mek2)
	from passlib.hash import pbkdf2_sha512 as m25
	mek3 = m25.encrypt(hash)
	print "%s[%s67%s] %sPBKDF2 SHA512      %s: %s%s" %(R,b,R,x,R,W,mek3)
	from passlib.hash import django_pbkdf2_sha1 as m25
	mek4 = m25.encrypt(hash)
	print "%s[%s68%s] %sDjango PBKDF2 SHA1 %s: %s%s" %(R,b,R,x,R,W,mek4)
	from passlib.hash import django_pbkdf2_sha256 as m25
	mek5 = m25.encrypt(hash)
	print "%s[%s69%s] %sDjangoPBKDF2SHA256 %s: %s%s" %(R,b,R,x,R,W,mek5)
	print "%s[%s70%s] %sArgon2             %s: %s%s%s" %(R,b,R,x,R,W,des,yy)
	s()
	os.system('echo "" | busybox timeout -t 3 termux-clipboard-set 2>/dev/null && busybox timeout -t 5 termux-toast "Success generate all Hash" 2>/dev/null')
	sys.exit()
def l():
	ghoff()
def ghoff():
	print ""
	print "%s[%s*%s] %sAlgorithm%s: %smd4" % (R,y,R,ww,R,Y)
	print "               %smd5" % Y
	print "               %ssha1" % Y
	print "               %ssha224" % Y
	print "               %ssha256" % Y
	print "               %ssha384" % Y
	print "               %ssha512" % Y
	print "               %sbase64" % Y
	print "               %sbase32" % Y
	print "               %sbase16" % Y
	print "               %sripemd160" % Y
	print "               %sadler32" % Y
	print "               %scrc32" % Y
	print "               %swhirlpool" % Y
	print "               %sbinary" % Y
	print "               %shexadecimal" % Y
	print """               mysql323
               mysql41
               mssql2000
               mssql2005
               des
               bsdicrypt
               bigcrypt
               crypt16
               md5crypt
               sha1crypt
               sha256crypt
               sha512crypt
               sunmd5crypt
               aprmd5crypt
               phpass
               cryptacularspbdf2
               dwinepbdf2
               djangosha1
               djangosha256
               gruppbkdf2sha512
               atlassianspbkdf2
               scram
               bsdnthash
               oracle11
               lanmanager
               nthash
               ciscotype7
               fhsp
               ciscoasa
               ciscopix
               descrypt
               djangosaltedmd5
               djangosaltedsha1
               djangodisabled
               djangodescrypt
               ldapmd5
               ldapsha1
               ldapsaltedmd5
               ldapsaltedsha1
               roundupplaintext
               ldaphexmd5
               ldaphexsha1
               lmhash
               bsdnthash
               ldapbsdicrypt
               ldapdescrypt
               ldapmd5crypt
               ldapsha256crypt
               ldapsha512crypt
               ldapsha1crypt
               ldappbkdf2sha1
               ldappbkdf2sha256
               ldappbkdf2sha512
               pbkdf2sha1
               pbkdf2sha256
               pbkdf2sha512
               djangopbkdf2sha1
               djangopbkdf2sha256
"""
       	print "               %sall" % Y
	print ""
	ghoff = raw_input(" \033[93mAlgorithm \033[31m>>>\033[00m ")
	if ghoff == 'md5':
		md5hash()
	elif ghoff == 'md4':
		md4()
	elif ghoff == 'sha1':
		sha1hash()
	elif ghoff == 'sha3':
		md5()
	elif ghoff == 'sha224':
		sha224hash()
	elif ghoff == 'sha256':
		sha256hash()
	elif ghoff == 'sha384':
		sha384hash()
	elif ghoff == 'sha512':
		sha512hash()
	elif ghoff == 'base64':
		base64hash(0)
	elif ghoff == 'base32':
		base64hash(1)
	elif ghoff == 'base16':
		base64hash(2)
	elif ghoff == 'ripemd160':
		ripemd160hash()
	elif ghoff == 'blake2s':
		blake2s()
	elif ghoff == 'blake2b':
		blake2b()
	elif ghoff == 'adler32':
		adler32()
	elif ghoff == 'crc32':
		crc32()
	elif ghoff == 'whirlpool':
		whirlpool()
	elif ghoff == 'binary':
		o,s = binary()
		print "%s%s" % (l_edr[0], bin(int(binascii.hexlify(s), 16)) if (o == 1) else binascii.unhexlify('%x' % int(s, 2)) if (o == 2) else '')
	elif ghoff == 'hexadecimal':
		o,s = binary()
		print "%s%s" % (l_edr[0], binascii.hexlify(s) if (o == 1) else binascii.unhexlify(s) if (o == 2) else '')
	elif ghoff == 'mysql323':
		mysql323()
	elif ghoff == 'mysql41':
		mysql41()
	elif ghoff == 'mssql2000':
                mssql2000()
        elif ghoff == 'mssql2005':
                mssql2005()
        elif ghoff == 'des':
                des()
        elif ghoff == 'bsdicrypt':
                bsdicrypt()
        elif ghoff == 'bigcrypt':
                bigcrypt()
        elif ghoff == 'crypt16':
                crypt16()
        elif ghoff == 'md5crypt':
                md5crypt()
        elif ghoff == 'sha1crypt':
                sha1crypt()
        elif ghoff == 'sha256crypt':
                sha256crypt()
        elif ghoff == 'sha512crypt':
                sha512crypt()
        elif ghoff == 'sunmd5crypt':
                sunmd5crypt
        elif ghoff == 'apachemd5crypt':
                apachemd5crypt()
        elif ghoff == 'phpass':
                phpass()
        elif ghoff == 'cryptacularspbdf2':
                cryptacularspbdf2()
        elif ghoff == 'djangosha1':
                djangosha1()
        elif ghoff == 'djangosha256':
                djangosha256()
	elif ghoff == 'gruppbkdf2sha512':
		gruppbkdf2sha512()
	elif ghoff == 'atlassianspbkdf2':
		atlassianspbkdf2()
	elif ghoff == 'scram':
		scram()
	elif ghoff == 'bsdnthash':
		bsdnthash()
	elif ghoff == 'oracle11':
		oracle11()
	elif ghoff == 'lanmanager':
		lanmanager()
	elif ghoff == 'nthash':
		nthash()
	elif ghoff == 'ciscotype7':
		ciscotype7()
	elif ghoff == 'fhsp':
		fhsp()
	elif ghoff == 'ciscoasa':
		ciscoasa()
	elif ghoff == 'ciscopix':
		ciscopix()
	elif ghoff == 'descrypt':
		descrypt()
	elif ghoff == 'djangosaltedmd5':
		djangosaltedmd5()
	elif ghoff == 'djangosaltedsha1':
		djangosaltedsha1()
	elif ghoff == 'djangodisabled':
		djangodisabled()
	elif ghoff == 'djangodescrypt':
		djangodescrypt()
	elif ghoff == 'ldapmd5':
		ldapmd5()
	elif ghoff == 'ldapsha1':
		ldapsha1()
	elif ghoff == 'ldapsaltedmd5':
		ldapsaltedmd5()
	elif ghoff == 'ldapsaltedmd5':
		ldapsaltedsha1()
	elif ghoff == 'roundupplaintext':
		roundupplaintext()
	elif ghoff == 'ldaphexmd5':
		ldaphexmd5()
	elif ghoff == 'ldaphexsha1':
		ldaphexsha1()
	elif ghoff == 'lmhash':
		lmhash()
	elif ghoff == 'bsdnthash':
		bsdnthash()
	elif ghoff == 'ldapbsdicrypt':
		ldapbsdicrypt()
	elif ghoff == 'ldapdel':
		ldapdescrypt()
	elif ghoff == 'ldapmd5crypt':
		ldapmd5crypt()
	elif ghoff == 'ldapsha256crypt':
		ldapsha256crypt()
	elif ghoff == 'ldapsha512crypt':
		ldapsha512crypt()
	elif ghoff == 'ldapsha1crypt':
		ldapsha1crypt()
	elif ghoff == 'ldappbkdf2sha1':
		ldappbkdf2sha1()
	elif ghoff == 'ldappbkdf2sha256':
		ldappbkdf2sha256()
	elif ghoff == 'ldappbkdf2sha512':
		ldappbkdf2sha512()
	elif ghoff == 'pbkdf2sha1':
		pbkdf2sha1()
	elif ghoff == 'pbkdf2sha256':
		pbkdf2sha256()
	elif ghoff == 'pbkdf2sha512':
		pbkdf2sha512()
	elif ghoff == 'djangopbkdf2sha1':
		djangopbkdf2sha1()
	elif ghoff == 'djangopbkdf2sha256':
		djangopbkdf2sha256()
	elif ghoff == 'all' or ghoff == 'ALL':
		try:
			all()
		except:
			print ""
			sys.exit()
	else:
		clear()
		l()
def updt():
	clear()
	print "%s[%s+%s] %sUpdating HashTool ..." % (R,Y,R,W)
	sleep(1.50)
	os.system("cd ~/ && rm -rf HashTool && git clone https://github.com/afelfgie/HashTool")
	os.system("cd ~/ && cd HashTool && chmod +x hash.py")
	sleep(2)
	s()
	print "%s[%s+%s] %sD%so%sn%se %s.%s.%s." % (R,Y,R,W,Y,W,Y,R,W,Y)
	sys.exit()
def about():
	print("""
{}=============================================
{}[+] Coded By : afelfgie
[+] Platform : python
[+] GitHub   : github.com/afelfgie
[+] Facebook : m.facebook.com/aries.isisas.3
[+] WhatsApp : +6285341899229
{}=============================================
""".format(R,W,R))
	print("{}[{}+{}] {}HashTool {}Is a hash Tool for crack a hash and hash a text".format(R,b,R,Y,W))
	print ""
	key = raw_input(""+W+"enter"+R+":"+b+"~"+Y+"#")
