/*
 * Copyright 2017-present Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.simpleRouter;

import com.google.common.collect.Maps;
import org.apache.felix.scr.annotations.*;
import org.onlab.packet.*;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Optional;
//import org.onosproject.xmpp_application.xmpp_service;


/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,enabled=true)
@Service
public class GatewayManager implements gatewayService{


    // Instantiates the relevant services.
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected DeviceService deviceService;

//    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
//    protected xmpp_service XmppService;

//    @Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY)
//    protected ovswitch_service ovservice;


    /*
     * Defining macTables as a concurrent map allows multiple threads and packets to
     * use the map without an issue.
     */
    protected Map<DeviceId, Map<Ip4Address, PortNumber>> routingTable = Maps.newConcurrentMap();
    private Map<Ip4Address, Ip4Address> local_remote = Maps.newConcurrentMap(); //for mapping arp replies
    private Map<Ip4Address, Ip4Address> src_dst = Maps.newConcurrentMap(); //matches on dst address
    private Map<Ip4Address, Ip4Address> dst_src = Maps.newConcurrentMap(); //matches on src address
    private Map<Ip4Address,PortNumber> access_map = Maps.newConcurrentMap(); //contains access rules
    private ApplicationId appId;
    private PacketProcessor processor;
    private DeviceListener deviceListener = new InnerDeviceListener();
    private MacAddress switch_mac;

    private final Logger log = LoggerFactory.getLogger(getClass());
    @Activate
    protected void activate() {
        log.info("SimpleRouter Started");
        appId = coreService.getAppId("org.onosproject.simpleRouter"); //equal to the name shown in pom.xml file
        deviceService.addListener(deviceListener);
        processor = new routerPacketProcessor();
        packetService.addProcessor(processor, PacketProcessor.director(3));

        /*
         * Restricts packet types to IPV4 and ARP by only requesting those types.
         */
        packetService.requestPackets(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4).build(), PacketPriority.REACTIVE, appId, Optional.empty());
        packetService.requestPackets(DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_ARP).build(), PacketPriority.REACTIVE, appId, Optional.empty());

        //populate_arped_candidates(Ip4Address.valueOf("192.168.1.101"));
        //translate_address("192.168.1.101","10.10.10.100",false);
        //translate_address("10.10.10.100","192.168.1.101",true);
        //populate_arped_candidates(Ip4Address.valueOf("10.0.1.1"));
        //populate_arped_candidates(Ip4Address.valueOf("10.0.2.1"));
        //populate_arped_candidates(Ip4Address.valueOf("10.0.3.1"));
    }

    @Deactivate
    protected void deactivate() {
        deviceService.removeListener(deviceListener);
        log.info("simpleRouter Stopped");
    }

    private class routerPacketProcessor implements PacketProcessor
    {
        @Override
        public void process(PacketContext pc) {
            //log.info(pc.toString());
            //log.info(pc.inPacket().receivedFrom().toString());
            ConnectPoint cp = pc.inPacket().receivedFrom();
            switch_mac = MacAddress.valueOf(getMacAddress(cp));
            //log.info("switch_mac "+switch_mac);
            System.out.println(pc.inPacket().parsed().getEtherType());
            System.out.println(Ethernet.TYPE_ARP);
            if (pc.inPacket().parsed().getEtherType()==Ethernet.TYPE_ARP)
            {
                ARP arp = (ARP)pc.inPacket().parsed().getPayload();
                byte[] b = arp.getTargetProtocolAddress();
                Ip4Address ipaddress = Ip4Address.valueOf(b);
                //log.info(pc.inPacket().parsed().getDestinationMACAddress().toString());
                if (local_remote.containsKey(ipaddress)) {
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(cp.port()).build();
                    Ethernet eth = createArpResponse(pc,ipaddress);
                    OutboundPacket packet = new DefaultOutboundPacket(cp.deviceId(),
                            treatment, ByteBuffer.wrap(eth.serialize()));
                    packetService.emit(packet);
                    log.info("sent out reply");
                }

            }
            else if (pc.inPacket().parsed().getEtherType()==Ethernet.TYPE_IPV4)
            {
                /*
                * check to see ip address matches
                * */
                IPv4 ipv4 = (IPv4) pc.inPacket().parsed().getPayload();
                Ip4Address src_add = Ip4Address.valueOf(ipv4.getSourceAddress());
                Ip4Address dst_add = Ip4Address.valueOf(ipv4.getDestinationAddress());
                //log.info(src_add.toString());
                //log.info(IpAddress.valueOf(ipv4.getSourceAddress()).toString());
                //log.info(IpAddress.valueOf(ipv4.getDestinationAddress()).toString());
               // log.info(dst_add.toString());
                PortNumber incoming_port = cp.port();
                /*
                if this node did not initiate dns request it does
                * not knows the ip4 address of the device that will connect to
                * it.
                * */
                PortNumber pn = access_map.get(dst_add);
                if (pn != null)
                    log.info("port number is "+pn.toLong());
                else
                    log.info("no port number found for address "+dst_add.toString());
                log.info("incoming port number is "+incoming_port.toLong());
                log.info("COMPARE PORT's ");
                if (pn != null && pn.exactlyEquals(incoming_port)){
                    if (!src_dst.containsKey(src_add))
                    {
                        Ip4Address mapped_src = find_free_address();
                        src_dst.putIfAbsent(src_add,mapped_src);
                        dst_src.putIfAbsent(mapped_src,src_add);
                        populate_arped_candidates(mapped_src);
                    }
                }
                if (dst_src.containsKey(dst_add)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            //.matchEthSrc(MacAddress.valueOf("00:00:00:00:00:01"))
                            .matchIPDst(IpPrefix.valueOf(dst_add.toString()+"/32"))
                            .build();
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            .setEthDst(MacAddress.valueOf("00:00:00:00:00:00"))
                            .setIpDst(IpAddress.valueOf(dst_src.get(dst_add).toString()))
                            .setOutput(PortNumber.portNumber(1))
                            .build();
                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            //.forDevice(cp.deviceId()).withPriority(PacketPriority.REACTIVE.priorityValue())
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            //.makeTemporary(60)
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info("installed flow rule dst to src");
                }
                else if (src_dst.containsKey(src_add)) {
                    TrafficSelector selector = DefaultTrafficSelector.builder()
                            .matchEthType(Ethernet.TYPE_IPV4)
                            //.matchEthSrc(MacAddress.valueOf("00:00:00:00:00:01"))
                            .matchIPSrc(IpPrefix.valueOf(src_add.toString()+"/32"))
                            .build();
                    TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                            .setEthDst(MacAddress.valueOf("FF:FF:FF:FF:FF:FF"))
                            .setIpSrc(IpAddress.valueOf(src_dst.get(src_add).toString()))
                            .setOutput(PortNumber.portNumber(4))
                            .build();
                    FlowRule fr = DefaultFlowRule.builder()
                            .withSelector(selector)
                            .withTreatment(treatment)
                            //.forDevice(cp.deviceId()).withPriority(PacketPriority.REACTIVE.priorityValue())
                            .forDevice(cp.deviceId()).withPriority(45000)
                            .makePermanent()
                            //.makeTemporary(60)
                            .fromApp(appId).build();
                    flowRuleService.applyFlowRules(fr);
                    log.info("installed flow rule src to dst");
                }

            }

        }
    }

    private Ip4Address find_free_address()
    {
        return Ip4Address.valueOf("10.10.10.101");
    }
    private class InnerDeviceListener implements DeviceListener
    {
        @Override
        public void event(DeviceEvent event)
        {
            switch(event.type())
            {
                case DEVICE_ADDED:
                    event.subject();
                    break;
                case PORT_ADDED:
                    event.subject();
                    log.info(event.subject().toString());
                    log.info(event.port().annotations().value("portMac"));
                    log.info(event.port().annotations().value("portName"));
                    break;
                case PORT_REMOVED:
                    event.subject();
                    log.info(event.subject().toString());
                    log.info(event.port().annotations().value("portMac"));
                    log.info(event.port().annotations().value("portName"));
                    break;
                case PORT_UPDATED:
                    event.subject();
                    log.info(event.subject().toString());
                    log.info(event.port().annotations().value("portMac"));
                    log.info(event.port().annotations().value("portName"));
                    break;
                default:
                    break;
            }
        }
    }

    private String getMacAddress(ConnectPoint cp)
    {
        String deviceID = cp.deviceId().toString();
        deviceID = deviceID.substring(deviceID.length()-12);
        char[] dID = deviceID.toCharArray();
        char[] mac = new char[dID.length+5];
        for (int i=0,j=0;i<mac.length;i++)
        {
            if (i!=0 && (i+1)%3==0)
                mac[i]=':';
            else
                mac[i]=dID[j++];
        }
        //log.info(did.substring(did.length()-12));
        //log.info(MacAddress.valueOf(did.substring(did.length()-12)).toString());
        String s_mac = new String(mac);
        //log.info(s_mac);
        return s_mac;
    }
    private Ethernet createArpResponse(PacketContext pc, Ip4Address ipaddress) {
        Ethernet request = pc.inPacket().parsed();
        //Ip4Address srcIP = Ip4Address.valueOf("10.0.1.1");
        //MacAddress srcMac = MacAddress.valueOf("A9:DC:3C:F1:6A:0B");
        Ethernet arpReply = ARP.buildArpReply(ipaddress, switch_mac, request);
        return arpReply;

    }

    private void populate_arped_candidates(Ip4Address ipaddress)
    {
        local_remote.putIfAbsent(ipaddress,ipaddress);
    }

    public void populate_arped_addresseses(String address){
        populate_arped_candidates(Ip4Address.valueOf(address));
    }

    public void translate_address(String match_address, String new_address, Boolean incoming){
        if (incoming==false)
            dst_src.putIfAbsent(Ip4Address.valueOf(match_address), Ip4Address.valueOf(new_address));
        else
            src_dst.putIfAbsent(Ip4Address.valueOf(match_address), Ip4Address.valueOf(new_address));

    }

    /* port binds to tunnel, one for each user
    * address binds to device, allow access to device
    * for incoming traffic from this port.*/
    public void allow_access(long port, String address)
    {
        access_map.putIfAbsent(Ip4Address.valueOf(address),PortNumber.portNumber(port));
    }

    public void remove_arped_candidates(String address){
        // will have to handle removal
    }


    public void do_something()
    {
        //log.info("Doing something ha ha ha");
    }


}
