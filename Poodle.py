# ================================================================================
#
# Poodle.py
#
# The objects in this file allow the MiM server to store the state and configuration
# of the global poodle object used by the MiM server
#
# Authors: Ryan Grandgenett 
# For:    IASC 8410-001
# Date:   March 2015 
#
# ================================================================================

#
# Represents a TargetSSLSession object
#		
class TargetSSLSession:
	def __init__(self):
		self.seq = 0			# TCP sequence number
		self.ack = 0			# TCP acknowledgement number
		self.next_ack = 0		# Next TCP acknowledgement number (server decryption response packet)
		return
		
#
# Represents a ExploitStatistics object
#		
class ExploitStatistics:
	def __init__(self):
		self.start_time = 0					# Start time of exploit		
		self.total_attempt_count = 0		# Total number of decryption attempts
		self.last_byte_attempt_count = 0	# Number of decryption attempts for previous decrypted byte 		
		return
#
# Represents a Poodle object
#		
class Poodle:
	def __init__(self):
		self.exploit_state = False						# Flag to determine if in exploit or find full pad block state
		self.exploit_stats = ExploitStatistics()		# Exploit statistics object
		self.client_ip = ''								# IP address of client (victim) 
		self.client_port = 0							# Port number of client (victim) https request program
		self.server_ip = ''								# IP address of server
		self.client_socket = None						# Socket to communicate with the victim https request program
		self.target_ssl_session = TargetSSLSession()	# Target SSL session object
		self.original_length = 0						# Original length of encrypted https data
		self.altered_length = 0							# Altered length of encrypted https data (Original length + block size)
		self.block_size = 0								# Block size of CBC algorithm (will be 8 for SSLv3)
		self.min_payload_size = 0						# Minimum payload size 
		self.modifed_payload = None						# Modified encrypted https request payload data
		self.message_url_data = ''						# URL data for victim https request	program to send			
		self.message_post_data = ''						# POST data for victim https request program to send				
		self.target_block = 0							# Current block to decrypt in the encrypted https request payload data
		self.end_block = 0								# Last block to decrypt in the encrypted https request payload data
		self.decrypt_offset = 0							# Current byte of target block to decrypt
		self.decrypted_block = ''						# Current plaintext of decrypted block
		self.plaintext = []								# Plaintext of all decrypted blocks
		return
		
	#	
	# Prints the poodle POC welcome message
	#
	def welcomeMessage(self):
		# Welcome text for start of exploit
		welcome_text = "\nPoodle Proof Of Concept by Ryan Grandgenett\n"
		
		# Poodle ascii art (found at http://www.retrojunkie.com/asciiart/animals/poodles.htm)
		poodle = (
'''     
            _,_
	   (;;;)              ,
	,__/a /;\            (;)
	(__   |;| _         //
	 '--. \;/;;)_____ (;;)
		@\(,;)'      '`/
		 (;;)          |
		   \  _____\   /
		  //||    \ \ |
		 || ||     ||||
		(;;(;;)   (;(;;)
		((_((_)  ((_((_)''')
				
		# Print welcome message
		print welcome_text + poodle
		return
