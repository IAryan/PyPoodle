# ================================================================================
#
# SSLData.py
#
# Dissect SSL Application Data packets. The objects in this file allow the MiM server 
# to easily break a stream of SSL application data packet bytes into various layers. 
#
# Authors: Ryan Grandgenett 
# For:    IASC 8410-001
# Date:   March 2015 
#
# ================================================================================

# Imports
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import copy

# 
# Represents an SSL Record Layer object
# 
class SSLRecordLayer:
	def __init__(self):
		self.contentType = None		# Content type of SSL record
		self.version = None			# Version of SSL record
		self.length = None			# Length of SSL record
		self.encData = None			# Encrypted data contained in SSL record
		self.block_size = 0			# Block size of encrypted data 

	# Returns a human-readable digest of the SSLRecordLayer data
	def __str__(self):
		return "SSL Record Layer \n" \
			+ "\tcontentType: %d\n" % (self.contentType) \
			+ "\tversion: %x\n" % (self.version) \
			+ "\tlength: %d\n" % (self.length) \
			+ "\tencData: %s\n" % (str(self.encData)) 

# 
# Represents SSL Data object
# 			
class SSLData:
	def __init__(self):
		self.records = []		# List of SSL records
	
	#
	# Breaks the encrypted data into blocks
	#
	@staticmethod
	def getBlocks(l, n):
		n = max(1, n)
		return [l[i:i + n] for i in range(0, len(l), n)]
		
	#	
	# Parses and stores all SSL records from the given packet
	#
	def readInPacket(self, pkt, block_size):
		# Create new SSL record layer object 
		ssl_record = SSLRecordLayer()
		# Set the block size of the records
		ssl_record.block_size = block_size
		
		# Get the length of the packet
		pktLength = len(pkt[TCP].payload)
		# Save the string representation of the packet
		pktpayload = str(pkt[TCP].payload)
		
		# Initialize counter value
		ctr = 0

		# While the counter is less than the packet length, parse the record information
		while ctr != pktLength:
			(ssl_record.contentType, ssl_record.version, ssl_record.length) = struct.unpack('>BHH',pktpayload[ctr:ctr+5])
			ctr += 5
			ssl_record.encData = pktpayload[ctr:ctr+ssl_record.length]
			ctr += ssl_record.length
			self.records.append(ssl_record)
			ssl_record = copy.deepcopy(ssl_record)
		
		# For each SSL record in the records list, break the encrypted data into blocks
		for record in self.records:
			cipherBlocks = struct.unpack('B' * len(record.encData), str(record.encData))
			cipherBlocks = list(cipherBlocks)
			cipherBlocks = SSLData.getBlocks(cipherBlocks, record.block_size)
			record.encData = cipherBlocks
			
	#	
	# Packs an SSL record data packet to be sent on the network
	#
	def packPacket(self):
		packet = ''
		# For each SSL record in the records list, pack the record information into a byte string
		for record in self.records:
			packet += struct.pack('>BHH', record.contentType, record.version, record.length)
			for block in record.encData:
				packet += struct.pack('B' * len(block), *block)
		return packet	
		
	#	
	# Checks if the packet is an SSL application data packet
	#
	def isAppData(self, pkt):
		# Verify this is an SSL packet
		if len(pkt[TCP].payload) > 0:
			pktpayload = str(pkt[TCP].payload)
			(content_type,) = struct.unpack('B',pktpayload[0])	
			if content_type == 23:
				return True
			else:
				return False
		else:
			return False
			
	#	
	# Checks if the packet is an SSL alert packet
	#
	def isAlert(self, pkt):
		# Verify this is an SSL packet
		if len(pkt[TCP].payload) > 0:
			pktpayload = str(pkt[TCP].payload)
			(content_type,) = struct.unpack('B',pktpayload[0])
			if content_type == 21:
				return True
			else:
				return False
		else:
			return False


			
