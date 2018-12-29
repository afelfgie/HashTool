#!/system/bin/python
# -*- coding: utf-8 -*-

#WARNA
R = '\033[31m'
ww = '\033[37m'
Y = '\033[33m'
w = '\033[00m'
i='\033[31m[\033[37m+\033[31m] \033[37m '
B = '\033[94m'
#BAHAN 1
import os,sys,time,hashlib,marshal
from time import sleep
#BAHAN 2
from core.ghoff import *
from core.choff import *
from core.banner import *
try:
    import passlib
except ImportError:
    os.system("clear")
    s()
    print("%s[%s!%s] %sModule %spasslib %sNot Installed") % (R,Y,R,ww,B,ww)
    print("%s[%s+%s] %spip install passlib") % (R,Y,R,ww)
    s()
    sys.exit()
#BAHAN 3
try:
	from memek.kontol import ngentot
	import kamar
	import adm
	import HackerKontolGoblokBangsat
except ImportError:
	pass

def cls():
	os.system("clear")
def clear():
	if 'linux' or 'unix' in sys.platform:
                cls()
        elif 'win' in sys.platform:
                os.system("cls")
        elif 'darwin' in sys.platform:
                os.sytem("cls")
        else:
                cls()
def keluar():
        cls()
        Banner()
        print " "
        print(i+"Thanks For Using HashTool ...")
        print(i+"Have a Bad Day ...")
	print(i+"Bye Bye ...")
        s()
        exit()
def infoo():
	print("{}[{}+{}] {}Coded by {}: {}afelfgie".format(R,Y,R,b,R,w))
	print("{}[{}+{}] {}Platform {}: {}python".format(R,Y,R,b,R,w))
	print("{}[{}+{}] {}Github   {}: {}github.com/afelfgie".format(R,Y,R,b,R,w))
def tya():
	print w+" "
	print "%s[%s1%s] %sGenerate Hash" % (R,Y,R,ww)
	print "%s[%s2%s] %sCrack Hash" % (R,Y,R,ww)
	print "%s[%s3%s] %sInfo" % (R,Y,R,ww)
	print "%s[%s0%s] \033[00mExit" % (R,Y,R)
	print w+" "
def main():
	clear()
	Banner()
	infoo()
	tya()
	try:
		memekontol = raw_input(adm_ngentod)
	except:
		keluar()
	if memekontol == '1':
		ghoff()
	elif memekontol == '2':
		choff()
	elif memekontol == '3':
		cls()
		Banner()
		about()
		main()
	elif memekontol == '0':
		keluar()
	else: # jangan coli ...
		p()
		print("%s[%s!%s] %sERROR: %s'%s' what? try again %s!") % (R,y,R,R,w,memekontol,R)
		sleep(1.10)
		main()



##########################
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		keluar()
##########################
