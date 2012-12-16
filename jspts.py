#!/usr/bin/python

#######################################
# Juniper Security Policy Traffic Summariser (JSPTS)
# Cooper Lees <me@cooperlees.com>
# Script to analyse a Juniper SRX Security Policy
# log and report a summary on traffic hitting a rule
# Last Updated: 20121216
#######################################

# TODO:
# - Test with IPv6

import datetime, os, re, socket, sys
from optparse import OptionParser

### EXAMPLE LOG ###

#session created source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 username(roles) packet-incoming-interface
# Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.83.99/40275->192.168.32.1/161 None 192.168.83.99/40275->192.168.32.1/161 None None 17 allow-all-out ICTNet StaffNet 23228 N/A(N/A) vlan.255

#session closed reason: source-address/source-port->destination-address/destination-port service-name nat-source-address/nat-source-port->nat-destination-address/nat-destination-port src-nat-rule-name dst-nat-rule-name protocol-id policy-name source-zone-name destination-zone-name session-id-32 packets-from-client(bytes-from-client) packets-from-server(bytes-from-server) elapsed-time application nested-application username(roles) packet-incoming-interface
#Apr 29 01:14:45 10.9.9.1 RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed ICMP error: 192.168.83.99/40275->192.168.32.1/161 None 192.168.83.99/40275->192.168.32.1/161 None None 17 allow-all-out ICTNet StaffNet 23228 1(703) 0(0) 1 UNKNOWN UNKNOWN N/A(N/A) vlan.255

### EXAMPLE LOG ###

class jspts:
	"Juniper Security Policy Traffic Summariser (JSPTS) to look for a rule in a Juniper SRX log and provides information about traffic hitting it"
	VERSION = "0.1"

	PROGNAME = "Juniper Security Policy Traffic Summariser (JSPTS)"
	polSplitReg = re.compile('.*RT.*: ')

	# Optional Analysis
	analyseNAT = False # Prob move to main options variable

	# Counters
	LINES_PARSED = 0
	POLICY_MATCHED = 0

	TCP_SESSIONS = 0
	UDP_SESSIONS = 0
	ICMP_SESSIONS = 0

	hostFlows = {}

	# Parse Arguments
	def parseOpts(self):
		parser = OptionParser(usage="%prog -s || -l logfile -p policyname [-v] (-h for more info + options)", version=self.VERSION, \
			description="%prog looks for a rule in a Juniper SRX log and provides information about the traffic hitting it - Cooper Ry Lees <me@cooperlees.com>")
	
		parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
			help="show informational/debug output (rather than just errors)")

		parser.add_option("-d", "--dns", action="store_true", dest="dns",
			help="resolve DNS name for report/summary")
		
		parser.add_option("-l", "--logfile", metavar="logfile", dest="logfile", type="string",
			help="logfile to be parsed")

		parser.add_option("-p", "--policyname", metavar="policyname", dest="policyname", type="string",
			help="Junos Security Policy to be investigated")

		parser.add_option("-P", "--genpolicy", action="store_true", dest="genpolicy",
			help="print SRX compatible policies rather than report on host flows")

		parser.add_option("-s", "--stdin", action="store_true", dest="read_from_stdin",
			help="parse from STDIN rather than a file")

#		parser.add_option("-t", "--threads", metavar="number", dest="threads", type="int",
#			help="specify maximum number of threads")

		return parser

	def convertProtoNum(self, proto_id):
		return {
			1: 	"ICMP",
			4:	"IPv4 Encapsulation",
			6:	"TCP",
			17:	"UDP",
			41:	"IPv6 Encapsulation",
			46:	"RSVP",
			47:	"GRE",
			50:	"ESP",
			51:	"AH",
			58:	"IPv6-ICMP",
			59:	"IPv6-NoNxt",
			60:	"IPv6-Opts",
			94:	"IPIP",
			103:	"PIM",
			112:	"VRRP",
		}.get(int(proto_id), "Undefined Protocol")

	def protoCount(self, proto_id):
		if proto_id == "1":
			self.ICMP_SESSIONS = self.ICMP_SESSIONS + 1
		elif proto_id == "17":
			self.UDP_SESSIONS = self.UDP_SESSIONS + 1
		else:
			self.TCP_SESSIONS = self.TCP_SESSIONS + 1

	def splitSRXipInfo(self, data):
		return re.split('/|(->)', data, 4)

	# Lets use the data from a line
	def parseLine(self, polReg, line):
		sessionCreate = False
		self.LINES_PARSED = self.LINES_PARSED + 1

		if polReg.search(line):
			self.POLICY_MATCHED = self.POLICY_MATCHED + 1
			noDate = self.polSplitReg.split(line.strip(), 1) #Strip Date and other eratta
			elements = noDate[1].split()
			if elements[0] == "session": #Remove session created data and flag
				sessionCreate = True
				elements.remove("session")
				elements.remove("created")
#			print elements #DEBUG
			ipData = self.splitSRXipInfo(elements[0])
			if self.analyseNAT == True: # TO be coded
				ipNATData = self.splitSRXipInfo(elements[2])
#			print ipData #DEBUG

			# Record Flow
			flowString = ipData[4] + "," + self.convertProtoNum(elements[5]) + "/" + ipData[6] + "," + elements[7] + "," + elements[8]
			if self.hostFlows.has_key(ipData[0]):
				if self.hostFlows[ipData[0]].count(flowString) == 0:
					self.hostFlows[ipData[0]].append(flowString)
			else:
				self.hostFlows[ipData[0]] = [flowString]
#			print flowString #DEBUG

			# Count Protocol
			self.protoCount(elements[5])

	# Print out templates SRX security policies
	def printPolicy(self, options):
		if options.verbose:
			sys.stderr.write("--> Generating specific Security Policy for all flows found ...")

		for i in sorted(self.hostFlows.iterkeys()):
			for j in sorted(self.hostFlows[i]):
				polData = j.split(",")
				proto = polData[1].split("/")
				if int(proto[1]) > 1024 and proto[0] != "ICMP":
					sys.stdout.write ("set applications application %s_%s protocol %s destination-port %s\n" % (proto[0], proto[1], proto[0].lower(), proto[1]))
				# Print a policy
				sys.stdout.write ("set security policies from from-zone %s to-zone %s policy allow-%s-%s match source-address %s destination-address %s application %s_%s\n" % (polData[2], polData[3], proto[0], proto[1], i, polData[0], proto[0], proto[1]))
				sys.stdout.write ("set security policies from from-zone %s to-zone %s policy allow-%s-%s then permit\n" % (polData[2], polData[3], proto[0], proto[1]))
				sys.stdout.write ("set security policies from from-zone %s to-zone %s policy allow-%s-%s then log session-close\n" % (polData[2], polData[3], proto[0], proto[1]))

	# Print out the rule summary ... 
	def printSummary(self, options):
		if options.verbose:
			sys.stdout.write ("\n-- %s Traffic Summary --\n" % options.policyname)

		print "%d unique source hosts generating Security Flows hitting '%s' policy" % ( len(self.hostFlows), options.policyname )
		print "- Traffic included:\n\t%d ICMP flows\n\t%d UDP Flows\n\t%d TCP and Other Flows\n" % ( self.ICMP_SESSIONS, self.UDP_SESSIONS, self.TCP_SESSIONS )
		if options.verbose:
			print "Output Format:\nDNS_NAME (IP):\n\t- DST_IP,DST_PORT,SRC_ZONE,DST_ZONE\n"

		for i in sorted(self.hostFlows.iterkeys()):
			if options.dns:
				try:
					dnsName = socket.gethostbyaddr(i)[0]
				except socket.herror:
					dnsName = i
			else:
				dnsName = i
			sys.stdout.write ("%s (%s):\n" % (dnsName, i))
			for j in sorted(self.hostFlows[i]):
				sys.stdout.write ("\t- %s\n" % j)

		if options.verbose:
			sys.stdout.write ("\n----------------------\n") 

	# Main Program
	def main(self):
		op = self.parseOpts() # Set OptionParser options
		(options, args) = op.parse_args() # Get arguments
		if options.policyname == None:
			op.error("You must specify a policy to summarise and file to parse (or STDIN).")

		# Need to cater for global policies
		if re.search("\(global\)", options.policyname):
			noGlobal = options.policyname[:-8]
			polReg = re.compile(noGlobal + "\(global\)")
		else:
			polReg = re.compile(options.policyname)
 
		sys.stdout.write ("-- %s v%s --\n" % (self.PROGNAME, self.VERSION)) # Print a header

		## Now parse the input line by line
		if options.read_from_stdin == True:
			for line in sys.stdin:
				self.parseLine(polReg, line)
		elif options.logfile != None and options.logfile != "":
			if os.path.exists(options.logfile):
				file = open(options.logfile)
				for line in file:
					self.parseLine(polReg, line)
				file.close()
			else:
				sys.stderr.write ("!-> Unable to locate logfile %s\n" % options.logfile)
				sys.exit(1)
		else:
			sys.stderr.write("!-> Ummm I need something to read to be useful. Please give me a -l or -s\n")
			sys.exit(69)

		if options.genpolicy:
			self.printPolicy(options)
		else:
			self.printSummary(options)

		if options.verbose:
			polPercent = 100 * float(self.POLICY_MATCHED) / float(self.LINES_PARSED)
			sys.stderr.write ("\n-> JSPTS has parsed %d lines finding %d matches for '%s' security policy (%.2f%%).\n" % ( self.LINES_PARSED, self.POLICY_MATCHED, options.policyname, polPercent ))
		
if __name__ == "__main__":
	z = jspts() # Gen Instance and Call Main
	z.main()

