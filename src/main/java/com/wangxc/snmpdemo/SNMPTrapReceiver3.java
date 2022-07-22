package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.mp.MPv1;
import org.snmp4j.mp.MPv2c;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultTcpTransportMapping;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.util.MultiThreadedMessageDispatcher;
import org.snmp4j.util.ThreadPool;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Vector;

/**
 * @author
 *
 */
public class SNMPTrapReceiver3 implements CommandResponder {

    private MultiThreadedMessageDispatcher dispatcher;
    private Snmp snmp = null;
    private Address listenAddress;
    private ThreadPool threadPool;
    private int n = 0;
    private long start = -1;

    public SNMPTrapReceiver3() {
    }

    public static void main(String[] args) {
        new SNMPTrapReceiver3().run();
    }

    private void run() {
        try {
            init();
//            snmp.addCommandResponder(this);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    private void init() throws UnknownHostException, IOException {
        threadPool = ThreadPool.create("Trap", 10);
        dispatcher = new MultiThreadedMessageDispatcher(threadPool, new MessageDispatcherImpl());

        listenAddress = GenericAddress.parse(System.getProperty("snmp4j.listenAddress", "udp:0.0.0.0/162"));  //SET THIS
        snmp = new Snmp(new MessageDispatcherImpl());
        snmp.addNotificationListener(listenAddress, this);
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv1());
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv2c());


        snmp.listen();
    }

    public void processPdu(CommandResponderEvent crEvent) {
        PDU pdu = crEvent.getPDU();
        if (pdu.getType() == PDU.V1TRAP) {

            PDUv1 pduV1 = (PDUv1) pdu;
            System.out.println("");
            System.out.println("===== NEW SNMP 1 TRAP RECEIVED ====");
            System.out.println("agentAddr " + pduV1.getAgentAddress().toString());
            System.out.println("enterprise " + pduV1.getEnterprise().toString());
            System.out.println("timeStamp" + String.valueOf(pduV1.getTimestamp()));
            System.out.println("genericTrap"+ String.valueOf(pduV1.getGenericTrap()));
            System.out.println("specificTrap " + String.valueOf(pduV1.getSpecificTrap()));
            System.out.println("snmpVersion " + String.valueOf(PDU.V1TRAP));
            System.out.println("communityString " + new String(crEvent.getSecurityName()));

        } else if (pdu.getType() == PDU.TRAP) {
            System.out.println("");
            System.out.println("===== NEW SNMP 2/3 TRAP RECEIVED ====");

            System.out.println("errorStatus " + String.valueOf(pdu.getErrorStatus()));
            System.out.println("errorIndex "+ String.valueOf(pdu.getErrorIndex()));
            System.out.println("requestID " +String.valueOf(pdu.getRequestID()));
            System.out.println("snmpVersion " + String.valueOf(PDU.TRAP));
            System.out.println("communityString " + new String(crEvent.getSecurityName()));

        }

        Vector<? extends VariableBinding> varBinds = pdu.getVariableBindings();
        if (varBinds != null && !varBinds.isEmpty()) {
            Iterator<? extends VariableBinding> varIter = varBinds.iterator();

            System.out.println("------variable binding list------");
            while (varIter.hasNext()) {
                VariableBinding vb = varIter.next();

                String syntaxstr = vb.getVariable().getSyntaxString();
                int syntax = vb.getVariable().getSyntax();
                System.out.println( "OID: " + vb.getOid());
                System.out.println("Value: " +vb.getVariable());
                System.out.println("syntaxstring: " + syntaxstr );
                System.out.println("syntax: " + syntax);
            }
            System.out.println("------variable binding list------");

        }
        System.out.println("==== TRAP END ===");
        System.out.println("");
    }
}