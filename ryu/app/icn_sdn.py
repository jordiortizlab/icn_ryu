# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2015 University of Murcia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import logging
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import icmp

from nose.tools import ok_

ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__


PROVIDER_IP='10.0.111.1'
PROVIDER_PORT=8000
PROVIDER_MAC='00:00:00:00:00'
CACHE_MAC='52:54:00:7d:d3:85'
PROXY_MAC='52:54:00:8b:53:1b'

class icn(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(icn, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_generic_flow(self, datapath, port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst)
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def add_non_http_flow(self, datapath, port, dst, out_port):
        # Add a flow for all the packets with low priority
        # Capture flows to port PROVIDER_PORT

        # All packets low priority flow
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst)

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # Port PROVIDER_PORT high priority flow to send these packets to controller
        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst,
                                                 tcp_dst=PROVIDER_PORT)
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]

        actions = [datapath.ofproto_parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                                           max_len=ofproto.OFPCML_NO_BUFFER)]


        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=5, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s : %s", dpid, in_port)

        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)

        arp_hdr  = None
        icmp_hdr = None
        eth_hdr  = None
        ipv4_hdr = None
        tcp_hdr  = None
        if header_list:
            if ETHERNET in header_list:
                eth_hdr = header_list[ETHERNET]
                self.logger.info("[DEBUG] parsed ETH:: " + str(eth_hdr))
            if ARP in header_list:
                arp_hdr = header_list[ARP]
                self.logger.info("[DEBUG]parsed ARP:: " + str(arp_hdr))
            if ICMP in header_list:
                icmp_hdr = header_list[ICMP]
                self.logger.info("[DEBUG]parsed ICMP:: " + str(icmp_hdr))
            if IPV4 in header_list:
                ipv4_hdr = header_list[IPV4]
                self.logger.info("[DEBUG]parsed IPv4:: " + str(ipv4_hdr))
            if TCP in header_list:
                tcp_hdr = header_list[TCP]
                self.logger.info("[DEBUG]parsed TCP:: " + str(tcp_hdr))

        # learn a mac address to avoid FLOOD next time.
        if arp_hdr != None:
            if arp_hdr.dst_mac != '00:00:00:00:00:00':
                # learn requester mac
                self.mac_to_port[dpid][arp_hdr.src_mac] = in_port
            else:
                self.mac_to_port[dpid][arp_hdr.dst_mac] = in_port
        if eth_hdr != None:
            self.mac_to_port[dpid][eth_hdr.src] = in_port


        self.logger.info(str(self.mac_to_port[dpid]))
        if eth_hdr.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth_hdr.dst]
            self.logger.info("OUT: " + str(dpid) + ":" + str(in_port))
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("OUT: " + str(dpid) + ":FLOOD")

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if tcp_hdr == None:
                self.add_non_http_flow(datapath, in_port, eth_hdr.dst, out_port)
            elif tcp_hdr.dst_port == PROVIDER_PORT:
                self.logger.info("DETECTED PROVIDER PORT!!!! Adding flow")
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                add_generic_flow(self, datapath, port, dst, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
