package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * @ClassName SnmpGet
 * @Description 发送SNMP GET请求
 * @Author wangx
 * @date 2022/7/18 16:41
 * @Version 1.0
 */
public class SnmpGet {

    public static void main(String[] args) {
//        v1();
//        v2c();
        v3();
    }

    /**
     * 发送snmp GET v1 version
     * snmpget -v 1 -c wangxc 39.105.213.2 .1.3.6.1.2.1.1.1.0
     */
    public static void v1() {
        try {
            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            transportMapping.listen();

            CommunityTarget target = new CommunityTarget();
            target.setAddress(GenericAddress.parse("udp:39.105.213.2/161"));
            target.setCommunity(new OctetString("wangxc"));
            target.setVersion(SnmpConstants.version1);
            target.setRetries(1);
            target.setTimeout(5000);

            PDU pdu = new PDU();
            pdu.setType(PDU.GET);
            pdu.add(new VariableBinding(new OID(".1.3.6.1.2.1.1.1.0")));

            ResponseEvent responseEvent = snmp.send(pdu, target);
            System.out.println(responseEvent.getResponse());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 发送snmp GET v2c version
     * snmpget -v 2c -c public 39.105.213.2 .1.3.6.1.2.1.1.1.0
     */
    public static void v2c() {
        try {
            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            transportMapping.listen();

            CommunityTarget target = new CommunityTarget();
            target.setAddress(GenericAddress.parse("udp:39.105.213.2/161"));
            target.setCommunity(new OctetString("wangxc"));
            target.setVersion(SnmpConstants.version2c);
            target.setRetries(1);
            target.setTimeout(5000);

            PDU pdu = new PDU();
            pdu.setType(PDU.GET);
            pdu.add(new VariableBinding(new OID(".1.3.6.1.2.1.1.1.0")));

            ResponseEvent responseEvent = snmp.send(pdu, target);
            System.out.println(responseEvent.getResponse());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 发送snmp GET v3
     * snmpget -v 3 -u testv3 -a MD5 -A mypassword -x DES -X mypassword -l authPriv 39.105.213.2 .1.3.6.1.2.1.1.1.0
     */
    public static void v3() {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            transportMapping.listen();

            snmp.getUSM().addUser(new OctetString("testv3"),
                    new UsmUser(new OctetString("testv3"),
                            AuthMD5.ID,
                            new OctetString("mypassword"),
                            PrivDES.ID,
                            new OctetString("mypassword")));

            UserTarget userTarget = new UserTarget();
            userTarget.setAddress(new UdpAddress("39.105.213.2/161"));
            userTarget.setVersion(SnmpConstants.version3);
            userTarget.setRetries(1);
            userTarget.setTimeout(5000);
            userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            userTarget.setSecurityName(new OctetString("testv3"));

            ScopedPDU scopedPDU = new ScopedPDU();
            scopedPDU.add(new VariableBinding(new OID(".1.3.6.1.2.1.1.1.0")));
            scopedPDU.setType(PDU.GET);

            ResponseEvent responseEvent = snmp.send(scopedPDU, userTarget);
            System.out.println(responseEvent.getRequest());
            System.out.println(responseEvent.getResponse());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
