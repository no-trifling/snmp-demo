package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

/**
 * @ClassName SnmpTrap
 * @Description 发送 SNMP TRAP 请求
 * @Author wangxc
 * @date 2022/7/19 9:31
 * @Version 1.0
 */
public class SnmpTrap {

    public static void main(String[] args) {
//        v1();
//        v2c();
        v3();
    }

    /**
     * 发送 SNMP TRAP v1
     *
     *   -v 1 TRAP-PARAMETERS:
     *          enterprise-oid agent trap-type specific-type uptime [OID TYPE VALUE]...
     *
     * snmptrap -v 1 -c public 39.105.213.2  1.3.6.1.4.1.8072.2.3.0.1   10.128.255.65  0  0  1000  1.3.6.1.4.1.8072.2.3.2.1.0 i 666666
     */
    public static void v1() {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            transportMapping.listen();

            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString("public"));
            target.setRetries(1);
            target.setTimeout(5000);
            target.setAddress(GenericAddress.parse("udp:39.105.213.2/162"));

            PDUv1 pdUv1 = new PDUv1();
            pdUv1.setType(PDUv1.V1TRAP);
            pdUv1.setEnterprise(new OID("1.3.6.1.4.1.8072.2.3.0.1"));
            pdUv1.setAgentAddress(new IpAddress("39.105.213.2"));
            pdUv1.setGenericTrap(PDUv1.LINKDOWN);
            pdUv1.setSpecificTrap(0);
            pdUv1.setTimestamp(1000L);
            pdUv1.add(new VariableBinding(new OID("1.3.6.1.4.1.8072.2.3.2.1.0"), new Integer32(111111)));

            ResponseEvent responseEvent = snmp.send(pdUv1, target);
            // TODO TRAP 无相应?
//            System.out.println(responseEvent.getResponse());


        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 发送 SNMP TRAP v2c
     *
     *   -v 2 TRAP-PARAMETERS:
     *          uptime trapoid [OID TYPE VALUE] ...
     *
     * snmptrap -v 2c -c public 39.105.213.2 2000 1.3.6.1.4.1.8072.2.3.0.1  1.3.6.1.4.1.8072.2.3.2.1.0 i 666666
     */
    public static void v2c() {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            transportMapping.listen();

            CommunityTarget target = new CommunityTarget();
            target.setAddress(GenericAddress.parse("udp:39.105.213.2/162"));
            target.setCommunity(new OctetString("public"));
            target.setVersion(SnmpConstants.version2c);
            target.setRetries(1);
            target.setTimeout(5000);

            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            pdu .add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(2000)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.4.1.8072.2.3.0.1")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.8072.2.3.2.1.0"), new Integer32(666666)));

            ResponseEvent responseEvent = snmp.send(pdu, target);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 发送 SNMP TRAP v3
     * v3 TRAP 除安全认证外 等同与 v2c
     *
     * snmptrap -v 3 -a SHA -A mypassword -x AES -X mypassword -l authPriv -u traptest -e 0x8000000001020304 localhost 0 linkUp.0
     */
    public static void v3() {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            USM usm = new USM(SecurityProtocols.getInstance(), OctetString.fromHexString("80:00:00:00:01:02:03:04"), 0);
            SecurityModels.getInstance().addSecurityModel(usm);
            transportMapping.listen();

            snmp.getUSM().addUser(new OctetString("traptest"),
                    new UsmUser(new OctetString("traptest"),
                            AuthSHA.ID,
                            new OctetString("mypassword"),
                            PrivAES128.ID,
                            new OctetString("mypassword")));

            UserTarget userTarget = new UserTarget();
            userTarget.setAddress(new UdpAddress("39.105.213.2/162"));
            userTarget.setVersion(SnmpConstants.version3);
            userTarget.setRetries(1);
            userTarget.setTimeout(5000);
            userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            userTarget.setSecurityName(new OctetString("traptest"));

            ScopedPDU scopedPDU = new ScopedPDU();
            scopedPDU.setType(PDU.TRAP);
            scopedPDU.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(0)));
            scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapOID, SnmpConstants.linkUp));

            ResponseEvent responseEvent = snmp.send(scopedPDU, userTarget);
            snmp.close();
            System.out.println(responseEvent.getRequest());
            System.out.println(responseEvent.getResponse());


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
