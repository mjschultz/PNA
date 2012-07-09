## URL Packet Sniffer
## It needs to be able to grab the URL from the packets and look for 'suspect' url's.
## once the suspect url is found, then it should send a notification to the network
## admin with the IP address of the computer and what they were attempting.


##Check to see if any other functions/libraries/files needed
##Download the C version of pycap if created, if not then im screwed
##do more research and watch more avatar

import sys
import socket
import pcap_wrap
import string
import os
import smtplib
import re


##The Regular Expression list
regexpr_list = ["^null$", "/\.\./\.\./\.\./", "\.\./\.\./config\.sys", "/\.\./\.\./\.\./autoexec\.bat", "/\.\./\.\./windows/user\.dat", "\\\x02\\\xb1", "\\\x04\\\x01", "\\\x05\\\x01", "\\\x90\\\x02\\\xb1\\\x02\\\xb1", "\\\x90\\\x90\\\x90\\\x90", "\\\xff\\\xff\\\xff\\\xff", "\\\xe1\\\xcd\\\x80", "\\\xff\xe0\\\xe8\\\xf8\\\xff\\\xff\\\xff-m", "\\\xc7f\\\x0c", "\\\x84o\\\x01", "\\\x81", "\\\xff\\\xe0\\\xe8", "\/c\+dir", "\/c\+dir\+c", "\.htpasswd", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "author\.exe", "boot\.ini", "cmd\.exe", "c%20dir%20c", "default\.ida", "fp30reg\.dll", "httpodbc\.dll", "nsiislog\.dll", "passwd$", "root\.exe", "shtml\.exe", "win\.ini", "xxxxxxxxxxxxxxxxxxxxxx"]

##For each packet captured, run this sequence


def packet_reader(payload):
	global list_Of_Request_Headers  ## Will be needed if we need to look for all of them

	if 'GET' in payload and 'HTTP/1.' in payload:
	
##		This if statement is an ideal scenario, making the assumption that the potential hacker
##		Did not alter the string to throw off the indexing.
		#needed_http_string = payload[3][ payload[3].index('GET'): payload[3].index('HTTP/1.1') + \
		#									len('HTTP/1.1') + 1]


##		Semi-Ideal situation. Only checks between 'GET' and the last 'HTTP/1.1'
##		Index string using index('HTTP', num) to see if duplicates were entered
##		to throw off url search

##		##create the two main variables, the previous and current indexes. will
##		##be the same at first, while loop will change them
		prev_num_index = payload.index('HTTP/1.')
		curr_num_index = prev_num_index

##		Preset dummyVar to force into while loop
		dummyVar = -1

##		while loop that will run until HTTP/1.1 is no longer in the string. Again,
##		I am assuming that the hacker can only tamper with anything between GET and
##		HTTP/1.1
		while dummyVar != curr_num_index:
			try:
				curr_num_index = payload.index('HTTP/1.', prev_num_index + 1)
				prev_num_index = curr_num_index
			except:

				dummyVar = curr_num_index


##		the final string needed is all of the content between GET and HTTP/1.1
##		use string indexing to get the correct part.
		needed_http_string = payload[ payload.index('GET'): curr_num_index + \
										len('HTTP/1.') + 1]
		alert_system(needed_http_string)
		return needed_http_string



##Sends email if I ever get to finding out how to do this
def send_email(To = 'cortez8652@att.net', From = 'intunesaccount@att.net', Crime = 'Network Breach'):
	return None


def alert_system(url_str):
	global regexpr_list
	for word in regexpr_list:
		print word
		#if word in url_str:
		compile_word = re.compile(word)
		if re.search(compile_word, url_str) != None:
			print word, "found in URL, attempting to contact network admin"
			try:
				send_email()
				print "Network Breach, administrator has been contacted"
			except:
				print "Network breached, unable to contact administrator"


## FIN ##
