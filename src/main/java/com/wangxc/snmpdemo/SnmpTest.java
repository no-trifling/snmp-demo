package com.wangxc.snmpdemo;

import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

/**
 * @ClassName SnmpTest
 * @Description TODO
 * @Author wangxc
 * @date 2022/7/13 17:19
 * @Version 1.0
 */
public class SnmpTest {

    public static void main(String[] args) throws IOException {
        Snmp snmp = new Snmp();

        Address targetAddress = GenericAddress.parse("udp:127.0.0.1/161");
        TransportMapping transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        USM usm = new USM(SecurityProtocols.getInstance(),
                new OctetString(MPv3.createLocalEngineID()), 0);
        SecurityModels.getInstance().addSecurityModel(usm);
        transport.listen();

        // add user to the USM
        snmp.getUSM().addUser(new OctetString("testv3"), new UsmUser(new OctetString("tesv3"), AuthMD5.ID, new OctetString("mypassword"), PrivDES.ID, new OctetString("mypassword")));

        // create the target
        UserTarget target = new UserTarget();
        target.setAddress(targetAddress);
        target.setRetries(1);
        target.setTimeout(5000);
        target.setVersion(SnmpConstants.version3);
        target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        target.setSecurityName(new OctetString("testv3"));

        // create the PDU
    }
}
