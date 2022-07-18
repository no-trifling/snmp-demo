package com.wangxc.snmpdemo;

import com.sun.deploy.ref.AppModel;
import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import org.snmp4j.transport.TransportMappings;

import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

/**
 * @ClassName SnmpGetNext
 * @Description 发送SNMPGET请求
 * @Author wangxc
 * @date 2022/7/15 14:20
 * @Version 1.0
 */
public class SnmpGetNext {

    public static void main(String[] args) {
//        v1();
//        v2c();
        v3();
    }


    /**
     * 发送GETNEXT v1 version
     * snmpgetnext -v 1 -c wangxc localhost 1.3.6
     */
    public static void v1() {

        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            transportMapping.listen();

            // 请求地址
            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString("wangxc"));
            target.setVersion(SnmpConstants.version1);
            InetAddress inetAddress = InetAddress.getByAddress(new byte[]{39, 105, (byte) 213, 2});
            UdpAddress udpAddress = new UdpAddress(inetAddress, 161);
            target.setAddress(udpAddress);

            // 创建发送的报文 PDU
            List<VariableBinding> list = new ArrayList<>();
            list.add(new VariableBinding(new OID("1.3.6")));
            PDU pdu = new PDU(PDU.GETNEXT, list);

            // 发送请求
            ResponseEvent responseEvent = snmp.send(pdu, target);
            PDU response = responseEvent.getResponse();
            System.out.println(response);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    /**
     * 发送v2c GETNEXT
     * snmpgetnext -v 2c -c wangxc localhost 1.3.6
     */
    public static void v2c() {
        try {

            Snmp snmp = new Snmp();

            TransportMapping transport = new DefaultUdpTransportMapping();
            snmp = new Snmp(transport);
            transport.listen();

            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString("wangxc"));
            target.setAddress(new UdpAddress("39.105.213.2/161"));
            target.setVersion(SnmpConstants.version2c);
            target.setRetries(1);
            target.setTimeout(5000);

            PDU pdu = new PDU();
            pdu.setType(PDU.GETNEXT);
            Vector variableBindings = pdu.getVariableBindings();
            variableBindings.add(new VariableBinding(new OID("1.3.6")));

            ResponseEvent response = snmp.send(pdu, target);
            System.out.println(response.getResponse());

        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /**
     * 发送v3版本 GETNEXT
     * snmpgetnext -v 3 -u testv3 -a MD5 -A mypassword -x DES -X mypassword -l authPriv localhost 1.3.6
     */
    public static void v3() {
        try {
            Address targetAddress = GenericAddress.parse("udp:39.105.213.2/161");
            TransportMapping transport = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transport);
            USM usm = new USM(SecurityProtocols.getInstance(),
                    new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            transport.listen();

            //  How a synchronous SNMPv3 message with authentication and privacy is then sent illustrates the following code snippet:

            // add user to the USM
            snmp.getUSM().addUser(new OctetString("testv3"),
                    new UsmUser(new OctetString("testv3"),
                            AuthMD5.ID,
                            new OctetString("mypassword"),
                            PrivDES.ID,
                            new OctetString("mypassword")));
            // create the target
            UserTarget target = new UserTarget();
            target.setAddress(targetAddress);
            target.setRetries(1);
            target.setTimeout(5000);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            target.setSecurityName(new OctetString("testv3"));

            // create the PDU
            PDU pdu = new ScopedPDU();
            pdu.add(new VariableBinding(new OID("1.3.6")));
            pdu.setType(PDU.GETNEXT);

            // send the PDU
            ResponseEvent response = snmp.send(pdu, target);
            // extract the response PDU (could be null if timed out)
            PDU responsePDU = response.getResponse();
            // extract the address used by the agent to send the response:
            Address peerAddress = response.getPeerAddress();

            Exception error = response.getError();
            PDU request = response.getRequest();
            Object userObject = response.getUserObject();
            System.out.println("responsePDU: " + responsePDU);
            System.out.println("peerAddress: " + peerAddress);
            System.out.println("error: " + error);
            System.out.println("request: " + request);
            System.out.println("userObject: " + userObject);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
