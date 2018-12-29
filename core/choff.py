# -*- coding: utf-8 -*-
#WARNA
R = '\033[31m'
ww = '\033[37m'
Y = '\033[93m'
y = '\033[33m'
LL = '\033[1;38;5;228m'
HB = '\033[1;38;5;32m'
RR = '\033[1;38;5;225m'
ll = '\033[1 38;5;223'
w = '\033[00m'
#BAHAN
import os
import sys
import time
import hashlib
def p():
	print ""
def md5hashc():
	p()
	hashc = raw_input("\033[31m[*] \033[37mHash     \033[31m:\033[00m ")
	wordlist = raw_input("\033[31m[*] \033[37mWordlist \033[31m:"+w+" ")
	try:
                words = open(wordlist, 'r')
        except IOError, e:
                print "%s[%s!%s] %sERROR%s: %s%s\n" % (R,y,R,w,R,w,e)
		exit()
        words = words.readlines()
        for word in words:
                hash = hashlib.md5(word[:-1])
                value = hash.hexdigest()
                if hashc == value:
			print "\n%s[%s+%s] %sWord%s:%s "+word+"" % (R,y,R,w,R,w)
			p()
			exit()
def sha1hashc():
	p()
        hashc = raw_input("\033[31m[*] \033[37mHash     \033[31m:\033[00m ")
        wordlist = raw_input("\033[31m[*] \033[37mWordlist \033[31m:"+w+" ")
	try:
                words = open(wordlist, 'r')
        except IOError, e:
                print "%s[%s!%s] %sERROR%s: %s%s\n" % (R,y,R,w,R,w,e)
		exit()
        words = words.readlines()
        for word in words:
                hash = hashlib.sha1(word[:-1])
                value = hash.hexdigest()
                if hashc == value:
			print "\n%s[%s+%s] %sWord%s:%s "+word+"" % (R,y,R,w,R,w)
			p()
			exit()
def sha224hashc():
	p()
        hashc = raw_input("\033[31m[*] \033[37mHash     \033[31m:\033[00m ")
        wordlist = raw_input("\033[31m[*] \033[37mWordlist \033[31m:"+w+" ")
        try:
                words = open(wordlist, 'r')
        except IOError, e:
                print "%s[%s!%s] %sERROR%s: %s%s\n" % (R,y,R,w,R,w,e)
                exit()
        words = words.readlines()
        for word in words:
                hash = hashlib.sha224(word[:-1])
                value = hash.hexdigest()
                if hashc == value:
			print "\n%s[%s+%s] %sWord%s:%s "+word+"" % (R,y,R,w,R,w)
			p()
			exit()
def sha256hashc():
	p()
        hashc = raw_input("\033[31m[*] \033[37mHash     \033[31m:\033[00m ")
        wordlist = raw_input("\033[31m[*] \033[37mWordlist \033[31m:"+w+" ")
        try:
                words = open(wordlist, 'r')
        except IOError, e:
                print "%s[%s!%s] %sERROR%s: %s%s\n" % (R,y,R,w,R,w,e)
                exit()
        words = words.readlines()
        for word in words:
                hash = hashlib.sha256(word[:-1])
                value = hash.hexdigest()
                if hashc == value:
                        print "\n%s[%s+%s] %sWord%s:%s "+word+"" % (R,y,R,w,R,w)
                        p()
                        exit()
def sha384hashc():
	p()
        hashc = raw_input("\033[31m[*] \033[37mHash     \033[31m:\033[00m ")
        wordlist = raw_input("\033[31m[*] \033[37mWordlist \033[31m:"+w+" ")
        try:
                words = open(wordlist, 'r')
        except IOError, e:
                print "%s[%s!%s] %sERROR%s: %s%s\n" % (R,y,R,w,R,w,e)
                exit()
        words = words.readlines()
        for word in words:
                hash = hashlib.sha384(word[:-1])
                value = hash.hexdigest()
                if hashc == value:
                        print "\n%s[%s+%s] %sWord%s:%s "+word+"" % (R,y,R,w,R,w)
                        p()
                        exit()
def sha512hashc():
	p()
        hashc = raw_input("\033[31m[*] \033[37mHash     \033[31m:\033[00m ")
        wordlist = raw_input("\033[31m[*] \033[37mWordlist \033[31m:"+w+" ")
        try:
                words = open(wordlist, 'r')
        except IOError, e:
                print "%s[%s!%s] %sERROR%s: %s%s\n" % (R,y,R,w,R,w,e)
                exit()
        words = words.readlines()
        for word in words:
                hash = hashlib.sha512(word[:-1])
                value = hash.hexdigest()
                if hashc == value:
                        print "\n%s[%s+%s] %sWord%s:%s "+word+"" % (R,y,R,w,R,w)
                        p()
                        exit()
def L():
	choff()
def choff():
	print ""
	print "%s[%s*%s] %sAlgorithm %s: %smd5" % (R,y,R,ww,R,Y)
	print "                %ssha1" % (Y)
	print "                %ssha224" % (Y)
	print "                %ssha256" % (Y)
	print "                %ssha384" % (Y)
	print "                %ssha512" % (Y)
	print ""
	try:
		choff = raw_input(" \033[93mAlgorithm \033[31m>>>\033[00m ")
	except:
		print "FUCK!"
	if choff == 'md5' or choff == 'MD5':
		md5hashc()
	elif choff == 'sha1' or choff == 'SHA1':
		sha1hashc()
	elif choff == 'sha224' or choff == 'SHA224':
		sha224hashc()
	elif choff == 'sha256' or choff == 'SHA256':
		sha256hashc()
	elif choff == 'sha384' or choff == 'SHA384':
		sha384hashc()
	elif choff == 'sha512' or choff == 'SHA512':
		sha512hashc()
	else:
		L()




