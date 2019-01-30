from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.app import simple_switch_13
import csv
import os
from ryu.lib import addrconv

ACL = "%s/Allowance.csv" % os.environ['HOME']

class L4Firewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Firewall, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        with open(ACL) as csvfile:
    		self.ConnAllowed = csv.DictReader(csvfile)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
    	datapath = ev.msg.datapath
    	ofproto = datapath.ofproto
    	parser = datapath.ofproto_parser
    	match = parser.OFPMatch()
    	actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
    	self.add_flow_to_switch(datapath, 0, match, actions)

    def add_flow_to_switch(self, datapath, priority, match, actions, buffer_id=None):
    	ofproto = datapath.ofproto
    	parser = datapath.ofproto_parser
    	inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
    	flow_mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
    	datapath.send_msg(flow_mod)
    	print "Flow entries Added to the switch. Flow Entry: {}".format(flow_mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

    	if ev.msg.msg_len < ev.msg.total_len:
    		print "Packet Truncated"
    	msg = ev.msg
    	datapath = msg.datapath
    	ofproto = datapath.ofproto
    	parser = datapath.ofproto_parser
    	in_port = msg.match['in_port']
	pkt = packet.Packet(msg.data)
	eth = pkt.get_protocols(ethernet.ethernet)[0]
	dst = eth.dst
	src = eth.src
	dpid = datapath.id
	print "Packet received with source: {}, destination: {}, source port: {} and Switch id: {}".format(src, dst, in_port, dpid)
	self.mac_to_port.setdefault(dpid, {})
	self.mac_to_port[dpid][src] = in_port
	if eth.ethertype == ether_types.ETH_TYPE_LLDP:
		return

	if pkt.get_protocols(arp.arp):
                print "ARP Packet was received"
		# dst = eth.dst
		# src = eth.src
		# dpid = datapath.id
		# self.mac_to_port.setdefault(dpid, {})
		# self.mac_to_port[dpid][src] = in_port
		if dst in self.mac_to_port[dpid]:
			port = self.mac_to_port[dpid][dst]
		else:
			port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(port)]
		#if port != ofproto.OFPP_FLOOD:
		#	match = parser.OFPMatch()
		#	self.add_flow_to_switch(datapath, 2, match, actions)
                data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data
		out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out_msg)
                print "ARP Packet was handled"
		return

	if pkt.get_protocols(icmp.icmp):
		print "ICMP REQUEST received from {} to {}".format(src, dst)
		if dst in self.mac_to_port[dpid]:
			port = self.mac_to_port[dpid][dst]
		else:
			port = ofproto.OFPP_FLOOD

		actions = [parser.OFPActionOutput(port)]

		if port != ofproto.OFPP_FLOOD:
			match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_type=0x0800, ip_proto=0x01)
			if msg.buffer_id != ofproto.OFP_NO_BUFFER:
				self.add_flow_to_switch(datapath, 2, match, actions, msg.buffer_id)
			else:
				self.add_flow_to_switch(datapath, 2, match, actions)
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data
		out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
		datapath.send_msg(out_msg)
		return

	with open(ACL) as csvfile:
		self.ConnAllowed = csv.DictReader(csvfile)
		print "Access List for Firewall Rules read"
		for control in self.ConnAllowed:
			srcIP = control['src_ip']
			dstIP = control['dst_ip']
			srcPORT = control['src_port']
			dstPORT = control['dst_port']
			print "Access Control List created"
                        priority = 12
			if srcIP == "any" and dstIP != "any" and srcPORT != "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=dstIP, tcp_src=int(srcPORT), tcp_dst=int(dstPORT))
				match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=dstIP, tcp_src=int(dstPORT), tcp_dst=int(srcPORT))
			elif srcIP != "any" and dstIP == "any" and srcPORT != "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, tcp_src=int(srcPORT), tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP, tcp_src=int(dstPORT), tcp_dst=int(srcPORT))
			elif srcIP != "any" and dstIP != "any" and srcPORT == "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, ipv4_dst=dstIP, tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP, ipv4_src=dstIP, tcp_src=int(dstPORT))
			elif srcIP != "any" and dstIP != "any" and srcPORT != "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, ipv4_dst=dstIP, tcp_src=int(srcPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP, ipv4_src=dstIP, tcp_dst=int(srcPORT))
			elif srcIP != "any" and dstIP != "any" and srcPORT == "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, ipv4_dst=dstIP)
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP, ipv4_src=dstIP)
			elif srcIP != "any" and dstIP == "any" and srcPORT == "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP)
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP)
			elif srcIP == "any" and dstIP != "any" and srcPORT == "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=dstIP)
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=dstIP)
			elif srcIP != "any" and dstIP == "any" and srcPORT == "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP, tcp_src=int(dstPORT))
			elif srcIP != "any" and dstIP == "any" and srcPORT != "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, tcp_src=int(srcPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=srcIP, tcp_dst=int(srcPORT))
			elif srcIP == "any" and dstIP != "any" and srcPORT == "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=dstIP, tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=dstIP, tcp_src=int(dstPORT))
			elif srcIP == "any" and dstIP != "any" and srcPORT != "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_dst=dstIP, tcp_src=int(srcPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=dstIP, tcp_dst=int(srcPORT))
			elif srcIP == "any" and dstIP == "any" and srcPORT == "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_src=int(dstPORT))
			elif srcIP == "any" and dstIP == "any" and srcPORT != "any" and dstPORT == "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_src=int(srcPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_dst=int(srcPORT))
			elif srcIP == "any" and dstIP == "any" and srcPORT != "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_src=int(srcPORT), tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, tcp_dst=int(srcPORT), tcp_src=int(dstPORT))
			elif srcIP != "any" and dstIP != "any" and srcPORT != "any" and dstPORT != "any":
				match = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=srcIP, ipv4_dst=dstIP, tcp_src=int(srcPORT), tcp_dst=int(dstPORT))
                                match_rev = parser.OFPMatch(eth_type=0x0800, ip_proto=0x06, ipv4_src=dstIP, ipv4_dst=srcIP, tcp_src=int(dstPORT), tcp_dst=int(srcPORT))
			else:
				match = parser.OFPMatch()
				match_rev = parser.OFPMatch()

			port = ofproto.OFPP_FLOOD
			actions = [parser.OFPActionOutput(port)]
			self.add_flow_to_switch(datapath, priority, match, actions)
                        priority +=1
			rev_actions = [parser.OFPActionOutput(port)]
			self.add_flow_to_switch(datapath, priority, match_rev, rev_actions)
                        priority +=1
			data = None
			if msg.buffer_id == ofproto.OFP_NO_BUFFER:
				data = msg.data
			out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
			datapath.send_msg(out_msg)

        match=parser.OFPMatch(eth_type=0x0800, ip_proto=0x06)
        instruction=[parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        flow_mod=parser.OFPFlowMod(datapath=datapath, priority=6, command=ofproto.OFPFC_ADD, match=match, instructions=instruction)
        print "FIREWALL restrictions: DROP ALL TCP PACKETS OTHER THAN IN ACL"
        datapath.send_msg(flow_mod)

        match=parser.OFPMatch(eth_type=0x0800, ip_proto=0x17)
        instruction=[parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        flow_mod=parser.OFPFlowMod(datapath=datapath, priority=5, command=ofproto.OFPFC_ADD, match=match, instructions=instruction)
        print "FIREWALL restrictions: DROP ALL UDP PACKETS"
        datapath.send_msg(flow_mod)


