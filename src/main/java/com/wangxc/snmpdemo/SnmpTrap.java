package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.util.ArrayList;
import java.util.List;

/**
 * @ClassName SnmpTrap
 * @Description 发送 SNMP TRAP 请求
 * @Author wangxc
 * @date 2022/7/19 9:31
 * @Version 1.0
 */
public class SnmpTrap {

    public static void main(String[] args) {

//
//        v1();
//        v2c();
//        v3();


        /**
         * 发送 SNMP v1 TRAP
         */
//        (String community, UdpAddress udpAddress, OID enterpriseOid, IpAddress agentAddress, int genericTrap, int specificTrap, long timeStamp, List<VariableBinding> variableBindings) {
        String community = "public";
//        UdpAddress udpAddress = new UdpAddress("127.0.0.1/162");
        UdpAddress udpAddress = new UdpAddress("39.105.213.2/162");
        OID enterpriseOid = new OID("1.3.6.1.4.1.8072.2.3.0.1");
        IpAddress ipAddress = new IpAddress("10.10.10.10");
        List<VariableBinding> variableBindings = new ArrayList<>();
//        variableBindings.add(new VariableBinding(new OID("1.3.6.1.4.1.8072.2.3.2.1.0"), new Integer32(111111)));
        v1(community, udpAddress, enterpriseOid, ipAddress, PDUv1.LINKDOWN, 0, 0L, variableBindings);

        /**
         * 发送 SNMP v2c TRAP
         */
//        public static void v2c(String community, UdpAddress udpAddress, List<VariableBinding> variableBindings) {
        List<VariableBinding> variableBindings2 = new ArrayList<>();
        variableBindings2.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(2000)));
        variableBindings2.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.4.1.8072.2.3.0.1")));
        variableBindings2.add(new VariableBinding(new OID("1.3.6.1.4.1.8072.2.3.2.1.0"), new Integer32(666666)));
//        v2c(community, udpAddress, variableBindings2);
//        informV2c(community, udpAddress, variableBindings2);



        /**
         * 发送 SNMP v3 TRAP
         */
        String username = "wangxc";
        String authenticationPassphrase = "mypassword";
        String privacyPassphrase = "mypassword";
        byte[] engineId = OctetString.fromHexString("80:00:00:00:01:02:03:04").toByteArray();
        engineId = "JL-CC-SNL".getBytes();
        engineId = "testsssssss".getBytes();
        String s = new OctetString(engineId).toHexString();

//        v3(udpAddress, username, AuthMD5.ID, authenticationPassphrase, PrivDES.ID, privacyPassphrase, engineId, new ArrayList<>());

    }

    static {
        ConsoleLogFactory consoleLogFactory = new ConsoleLogFactory();
        consoleLogFactory.getRootLogger().setLogLevel(LogLevel.DEBUG);
        LogFactory.setLogFactory(consoleLogFactory);
    }


    /**
     * 发送 SNMP TRAP v1
     * <p>
     * -v 1 TRAP-PARAMETERS:
     * enterprise-oid agent trap-type specific-type uptime [OID TYPE VALUE]...
     * <p>
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

    public static void v1(String community, UdpAddress udpAddress, OID enterpriseOid, IpAddress agentAddress, int genericTrap, int specificTrap, long timeStamp, List<VariableBinding> variableBindings) {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
            transportMapping.listen();

            CommunityTarget target = new CommunityTarget();
            target.setCommunity(new OctetString(community));
            target.setRetries(1);
            target.setTimeout(5000);
            target.setAddress(udpAddress);

            PDUv1 pdUv1 = new PDUv1();
            pdUv1.setType(PDUv1.V1TRAP);
            pdUv1.setEnterprise(enterpriseOid);
            pdUv1.setAgentAddress(agentAddress);
            pdUv1.setGenericTrap(genericTrap);
            pdUv1.setSpecificTrap(specificTrap);
            pdUv1.setTimestamp(timeStamp);
            pdUv1.addAll(variableBindings);

            ResponseEvent responseEvent = snmp.send(pdUv1, target);
            // TODO TRAP 无相应?
//            System.out.println(responseEvent.getResponse());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * 发送 SNMP TRAP v2c
     * <p>
     * -v 2 TRAP-PARAMETERS:
     * uptime trapoid [OID TYPE VALUE] ...
     * <p>
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
            pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(2000)));
            pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID("1.3.6.1.4.1.8072.2.3.0.1")));
            pdu.add(new VariableBinding(new OID("1.3.6.1.4.1.8072.2.3.2.1.0"), new Integer32(666666)));

            ResponseEvent responseEvent = snmp.send(pdu, target);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void v2c(String community, UdpAddress udpAddress, List<VariableBinding> variableBindings) {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);

            CommunityTarget target = new CommunityTarget();
            target.setAddress(udpAddress);
            target.setCommunity(new OctetString(community));
            target.setVersion(SnmpConstants.version2c);
            target.setRetries(1);
            target.setTimeout(5000);

            PDU pdu = new PDU();
            pdu.setType(PDU.TRAP);
            pdu.addAll(variableBindings);

            snmp.send(pdu, target);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void informV2c(String community, UdpAddress udpAddress, List<VariableBinding> variableBindings) {
        try {

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);

            CommunityTarget target = new CommunityTarget();
            target.setAddress(udpAddress);
            target.setCommunity(new OctetString(community));
            target.setVersion(SnmpConstants.version2c);
            target.setRetries(1);
            target.setTimeout(5000);

            PDU pdu = new PDU();
            pdu.setType(PDU.INFORM);
            pdu.addAll(variableBindings);

            snmp.listen();
            ResponseEvent responseEvent = snmp.send(pdu, target);
            System.out.println(responseEvent.getResponse());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 发送 SNMP TRAP v3
     * v3 TRAP 除安全认证外 等同与 v2c
     * <p>
     * snmptrap -v 3 -a SHA -A mypassword -x AES -X mypassword -l authPriv -u traptest -e 0x8000000001020304 localhost 0 linkUp.0
     */
    public static void v3() {
        try {

            byte[] engineId = {-128, 0, 0, 0, 1, 2, 3, 4};

            DefaultUdpTransportMapping transportMapping = new DefaultUdpTransportMapping();
            Snmp snmp = new Snmp(transportMapping);
//            USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
            USM usm = new USM();
            SecurityModels.getInstance().addSecurityModel(usm);

            snmp.getUSM().addUser(new OctetString("traptest"),
                    OctetString.fromHexString("80:00:00:00:01:02:03:04"),
                    new UsmUser(new OctetString("traptest"),
                            AuthSHA.ID,
                            new OctetString("mypassword"),
                            PrivAES128.ID,
                            new OctetString("mypassword")));
            snmp.setLocalEngine(OctetString.fromHexString("80:00:00:00:01:02:03:04").getValue(), 0, 0);

            UserTarget userTarget = new UserTarget();
            userTarget.setAddress(new UdpAddress("39.105.213.2/162"));
            userTarget.setVersion(SnmpConstants.version3);
            userTarget.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
            userTarget.setSecurityName(new OctetString("traptest"));

            ScopedPDU scopedPDU = new ScopedPDU();
            scopedPDU.setType(PDU.TRAP);
            scopedPDU.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(0)));
            scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapOID, SnmpConstants.linkUp));

            snmp.send(scopedPDU, userTarget);
            snmp.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void v3(UdpAddress udpAddress, String username, OID authenticationProtocol, String authenticationPassphrase,
                          OID privacyProtocol, String privacyPassphrase, byte[] engineID, List<VariableBinding> variableBindings) {

        try {
            Snmp snmp = new Snmp(new DefaultUdpTransportMapping());

            USM usm = new USM();
            SecurityModels.getInstance().addSecurityModel(usm);
            snmp.getUSM().addUser(new OctetString(username), new OctetString(engineID),
                    new UsmUser(new OctetString(username), authenticationProtocol, new OctetString(authenticationPassphrase), privacyProtocol, new OctetString(privacyPassphrase)));
            snmp.setLocalEngine(engineID, 0, 0);

            UserTarget userTarget = new UserTarget();
            userTarget.setAddress(udpAddress);
            userTarget.setVersion(SnmpConstants.version3);
            userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            userTarget.setSecurityName(new OctetString(username));

            ScopedPDU scopedPDU = new ScopedPDU();
            scopedPDU.setType(PDU.TRAP);
//            scopedPDU.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(0)));
//            scopedPDU.add(new VariableBinding(SnmpConstants.snmpTrapOID, SnmpConstants.linkUp));
            scopedPDU.addAll(variableBindings);

            snmp.send(scopedPDU, userTarget);
            snmp.close();

        } catch (Exception e) {
            e.printStackTrace();
        }


    }
}
