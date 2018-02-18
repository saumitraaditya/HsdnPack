

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
        package org.onosproject.xmpp_application;
        import com.google.common.collect.Maps;
        import com.google.common.collect.Sets;
        import io.netty.util.concurrent.SingleThreadEventExecutor;
        import org.apache.felix.scr.annotations.Component;
        import org.apache.felix.scr.annotations.Service;
        import org.apache.felix.scr.annotations.Activate;
        import org.apache.felix.scr.annotations.Deactivate;
        import org.apache.felix.scr.annotations.ReferenceCardinality;
        import org.apache.felix.scr.annotations.Reference;
        import org.jivesoftware.smack.chat2.Chat;
        import org.jivesoftware.smack.chat2.ChatManager;
        import org.jxmpp.jid.EntityBareJid;
        import org.jxmpp.jid.Jid;
        import org.jxmpp.jid.impl.JidCreate;
        import org.onlab.packet.IP;
        import org.onlab.packet.IpAddress;
        import org.onlab.packet.TpPort;
        import org.onlab.util.ItemNotFoundException;
        import org.onosproject.cluster.ClusterService;
        import org.onosproject.core.ApplicationId;
        import org.onosproject.core.CoreService;


        import org.onosproject.simpleRouter.gatewayService;
        import org.slf4j.Logger;
        import org.slf4j.LoggerFactory;
        import java.util.ArrayList;
        import java.util.HashSet;
        import java.util.List;
        import java.util.Map;
        import java.util.Set;

        import java.util.concurrent.ExecutorService;
        import java.util.Optional;
        import java.util.NoSuchElementException;
        import java.util.concurrent.atomic.AtomicLong;

        import static java.util.concurrent.Executors.unconfigurableExecutorService;
        import static org.onlab.util.Tools.isNullOrEmpty;
        import static java.util.concurrent.Executors.newSingleThreadExecutor;
        import static org.onlab.util.Tools.groupedThreads;

        import org.jivesoftware.smack.XMPPConnection;
        import org.jivesoftware.smack.XMPPException;
        import org.jivesoftware.smack.filter.StanzaExtensionFilter;
        import org.jivesoftware.smack.filter.StanzaFilter;
        import org.jivesoftware.smack.packet.ExtensionElement;
        import org.jivesoftware.smack.packet.Message;
        import org.jivesoftware.smack.packet.Stanza;
        import org.jivesoftware.smack.provider.EmbeddedExtensionProvider;
        import org.jivesoftware.smack.provider.ProviderManager;
        import org.jivesoftware.smack.tcp.XMPPTCPConnection;
        import org.jivesoftware.smack.tcp.XMPPTCPConnectionConfiguration;
        import org.jivesoftware.smack.util.XmlStringBuilder;
        import org.jxmpp.stringprep.XmppStringprepException;
        import org.jivesoftware.smack.AbstractXMPPConnection;
        import org.jivesoftware.smack.ConnectionConfiguration;
        import org.jivesoftware.smack.SmackException;
        import org.jivesoftware.smack.StanzaCollector;
        import org.jivesoftware.smack.StanzaListener;
        import java.io.IOException;



/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,enabled=true)
public class XmppManager implements xmpp_service{

    private final Logger log = LoggerFactory.getLogger(getClass());
    private ApplicationId appId;
    private static final int DPID_BEGIN = 4;
    private static final int OFPORT = 6653;
    protected Map<String, String> tag_sender = Maps.newConcurrentMap();

    XMPPTCPConnectionConfiguration config;
    AbstractXMPPConnection conn;
    StanzaFilter filter;
    StanzaCollector collector;
    StanzaListener listener;


    @Reference(cardinality=ReferenceCardinality.MANDATORY_UNARY)
    protected CoreService coreService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected gatewayService GatewayService;

    private Thread thread;
    private volatile boolean xmpp_active = false;

    @Activate
    public void activate() {
        log.info("XmppAgent started");
        appId = coreService.getAppId("org.onosproject.xmpp_app");
//        try
//        {
//            initialize_xmpp();
//        }
//        catch (Exception e)
//        {
//            log.info(e.toString());
//        }
        thread = new Thread(new xmpp_initializer());
        thread.start();


    }

    @Deactivate
    public void deactivate() {
        xmpp_active = false;
    }

    public void send(String to, String setup, String query, String response, String tag)
    {
        Message message = new Message();
        message.setType(Message.Type.chat);
        DNS_Extension dns_extension = new DNS_Extension();
        dns_extension.set_interfaces(setup,query,response,tag);
        message.addExtension(dns_extension);
        ChatManager chatManager = ChatManager.getInstanceFor(conn);
        try {
            EntityBareJid jid = JidCreate.entityBareFrom(to);
            Chat chat = chatManager.chatWith(jid);
            chat.send(message);
        } catch (Exception e)
        {
            log.info(e.toString());
        }

    }

    public void handle(DNS_Extension dns_extension, String orig_sender)
    {
        String setup = dns_extension.get_setup();
        String query = dns_extension.get_query();
        String admin = query.split("\\.")[1];
        String tag = dns_extension.get_tag();
        String response = dns_extension.get_resp();

        switch(setup)
        {
            case "QUERY":
                tag_sender.putIfAbsent(tag,orig_sender);
                //send(orig_sender,"RESP",query,"127.0.0.1",tag);
                send(admin+"_gnv_gw@xmpp.ipop-project.org","QUERY_IC",query,response,tag);
                break;
            case "RESP":
                break;
            case "QUERY_IC":
                /* need to do a name query to check availability and to get back IP address of the device*/
                tag_sender.putIfAbsent(tag,orig_sender);
                String dname = query.split("\\.")[0];
                send(dname+"@xmpp.ipop-project.org","NAME_QUERY",query,response,tag);
                //GatewayService.allow_access(4,"10.10.10.100"); // hardcoded for now.
                //send(orig_sender,"RESP_IC",query,"10.10.10.100",tag);
                break;
            case "RESP_IC":
                String mapped_addr = find_free_address();
                String remote_addr = response;
                GatewayService.populate_arped_addresseses(mapped_addr);
                GatewayService.translate_address(mapped_addr,remote_addr,false);
                GatewayService.translate_address(remote_addr,mapped_addr,true);
                String target = tag_sender.get(tag);
                send(target,"RESP",query,mapped_addr,tag);
                break;
            case "NAME_RESP":
                String sendto = tag_sender.get(tag);
                GatewayService.allow_access(1,response);
                send(sendto,"RESP_IC",query,response,tag);
                break;
        }
    }

    private class xmpp_initializer implements Runnable
    {
        public void run()
        {
            try
            {
                GatewayService.do_something();
                xmpp_active = true;
                initialize_xmpp();
            }
            catch (Exception e)
            {
                log.info(e.toString());
            }
        }
    }

    private String find_free_address()
    {
        return "10.10.10.101";
    }
    private void initialize_xmpp() throws SmackException, IOException, XMPPException, InterruptedException
    {
        config = XMPPTCPConnectionConfiguration.builder()
                .setUsernameAndPassword("alice_gnv_gw@xmpp.ipop-project.org", "ipop_alice_gw")
                .setXmppDomain("xmpp.ipop-project.org")
                .setPort(5222)
                .setSecurityMode(ConnectionConfiguration.SecurityMode.disabled)
                .addEnabledSaslMechanism("PLAIN")
                .build();
        conn = new XMPPTCPConnection(config);
        filter = new StanzaExtensionFilter(DNS_Extension.EL,DNS_Extension.NS);
        collector = conn.createStanzaCollector(filter);
        listener = new StanzaListener()
        {
            public void processStanza(Stanza stanza)
            {
                String msg = stanza.toString();
                Jid sender = stanza.getFrom();
                System.out.println(stanza.toXML());
                ExtensionElement ext = stanza.getExtension(DNS_Extension.NS);
                DNS_Extension dns_ext = (DNS_Extension) ext;
                //System.out.println(dns_ext.toXML());
                //System.out.println(dns_ext.toString());
                //dns_ext.get_interfaces();
                //System.out.println(msg);
                String query = dns_ext.get_query();
                log.info(dns_ext.toXML().toString());
                log.info(msg);
                //send(sender.toString(),"RESP",query,"127.0.0.1","747364346");
                handle(dns_ext,sender.toString());

            }
        };
        conn.addAsyncStanzaListener(listener,filter);
        ProviderManager.addExtensionProvider(DNS_Extension.EL, DNS_Extension.NS, new DNS_Extension.Provider());
        conn.connect();
        conn.login();
//        while (xmpp_active)
//        {
//            continue;
//        }
    }



}

