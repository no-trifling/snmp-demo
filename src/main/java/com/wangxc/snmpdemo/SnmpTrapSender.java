
package com.wangxc.snmpdemo;

import java.io.IOException;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.PDUv1;
import org.snmp4j.SNMP4JSettings;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.Priv3DES;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

public class SnmpTrapSender {

    private Snmp snmp = null;

    private Address targetAddress = null;

    private TransportMapping transport = null;

    //UsmUser 的userName
    private String username1 = "nmsAdminNaNp";
    private String username2 = "nmsAdmin2ANp";
    private String username3 = "nmsAdmin3ap";
    //认证协议的密码  如MD5
    private String authPassword = "nmsAuthKey";
    //加密协议密码  如 DES AES
    private String privPassword = "nmsPrivKey";

    public static void main(String[] args) {

        SnmpTrapSender poc = new SnmpTrapSender();

        try {
            poc.init();

            poc.sendV1Trap();

            poc.sendV2cTrap();

            poc.sendV3TrapNoAuthNoPriv();
            poc.sendV3AUTH_NOPRIV();

            poc.sendV3Auth();
            poc.sendV3AUTH_PRIV();


        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void init() throws IOException {
        //目标主机的ip地址 和 端口号
        targetAddress = GenericAddress.parse("udp:127.0.0.1/162");
        transport = new DefaultUdpTransportMapping();
        snmp = new Snmp(transport);
        transport.listen();
    }

    /**
     * Snmp V1 测试发送Trap
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV1Trap() throws IOException {
        PDUv1 pdu = new PDUv1();
        VariableBinding v = new VariableBinding();
        v.setOid(SnmpConstants.sysName);
        v.setVariable(new OctetString("Snmp Trap V1 Test"));
        pdu.add(v);
        pdu.setType(PDU.V1TRAP);

        // set target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);
        // retry times when commuication error
        target.setRetries(2);
        // timeout
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version1);
        // send pdu, return response
        return snmp.send(pdu, target);
    }

    /**
     * Snmp V2c 测试发送Trap
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV2cTrap() throws IOException {

        PDU pdu = new PDU();
        VariableBinding v = new VariableBinding();
        v.setOid(SnmpConstants.sysName);
        v.setVariable(new OctetString("Snmp Trap V2 Test"));
        pdu.add(v);
        pdu.setType(PDU.TRAP);

        // set target
        CommunityTarget target = new CommunityTarget();
        target.setCommunity(new OctetString("public"));
        target.setAddress(targetAddress);

        // retry times when commuication error
        target.setRetries(2);
        target.setTimeout(1500);
        target.setVersion(SnmpConstants.version2c);
        // send pdu, return response
        return snmp.send(pdu, target);

    }

    /**
     * SnmpV3 不带认证加密协议.
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV3TrapNoAuthNoPriv() throws IOException {
        SNMP4JSettings.setExtensibilityEnabled(true);
        SecurityProtocols.getInstance().addDefaultProtocols();

        UserTarget target = new UserTarget();
        target.setVersion(SnmpConstants.version3);

        try {
            transport = new DefaultUdpTransportMapping();
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        byte[] enginId = "JL-CC-SNL".getBytes();
        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
                enginId), 500);
        SecurityModels secModels = SecurityModels.getInstance();
        if (snmp.getUSM() == null) {
            secModels.addSecurityModel(usm);
        }

        target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);

        target.setAddress(targetAddress);

        ScopedPDU pdu = new ScopedPDU();
        pdu.setType(PDU.NOTIFICATION);
        VariableBinding v = new VariableBinding();
        v.setOid(SnmpConstants.sysName);
        v.setVariable(new OctetString("Snmp Trap V3 Test sendV3Trap NoAuthNoPriv"));
        pdu.add(v);

        snmp.setLocalEngine(enginId, 500, 1);
        return snmp.send(pdu, target);
    }

    /**
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV3Auth() throws IOException {
        SNMP4JSettings.setExtensibilityEnabled(true);
        SecurityProtocols.getInstance().addDefaultProtocols();

        UserTarget target = new UserTarget();
        target.setSecurityName(new OctetString(username3));
        target.setVersion(SnmpConstants.version3);

        try {
            transport = new DefaultUdpTransportMapping();
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        byte[] enginId = "JL-CC-SNL".getBytes();
        USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(
                enginId
//                MPv3.createLocalEngineID()
        ), 500);
        SecurityModels secModels = SecurityModels.getInstance();
        synchronized (secModels) {
            if (snmp.getUSM() == null) {
                secModels.addSecurityModel(usm);
            }
            snmp.getUSM().addUser(
                    new OctetString(username3),
                    new OctetString(enginId),
                    new UsmUser(new OctetString(username3), AuthMD5.ID,
                            new OctetString(authPassword), Priv3DES.ID,
                            new OctetString(privPassword)));
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
//            target.setAuthoritativeEngineID(enginId);
            target.setAddress(targetAddress);

            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.NOTIFICATION);
            VariableBinding v = new VariableBinding();
            v.setOid(SnmpConstants.sysName);
            v.setVariable(new OctetString("Snmp Trap V3 Test sendV3Auth"));
            System.out.println("Snmp Trap V3 Test sendV3Auth");
            pdu.add(v);

            snmp.setLocalEngine(enginId, 500, 1);
            ResponseEvent send = snmp.send(pdu, target);
            //System.out.println(send.getError());

            return send;
        }
    }


    /**
     * 测试SnmpV3  带认证协议，无加密协议
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV3AUTH_NOPRIV() throws IOException{
        OctetString userName2 = new OctetString(username2);
        OctetString authPass = new OctetString(authPassword);
        OctetString authPass2 = new OctetString("authPassword2");
        OctetString privPass = new OctetString(privPassword);

        TransportMapping transport;
        transport = new DefaultUdpTransportMapping();

        Snmp snmp = new Snmp(transport);
        //MPv3.setEnterpriseID(35904);
        byte[] enginId = "JL-CC-SNL".getBytes();
        USM usm = new USM(SecurityProtocols.getInstance(),
                new OctetString(
//                        MPv3.createLocalEngineID()
                        enginId
                ), 500);
        SecurityModels.getInstance().addSecurityModel(usm);

        UserTarget target = new UserTarget();


        SecurityModels secModels = SecurityModels.getInstance();
        synchronized (secModels) {
            if (snmp.getUSM() == null) {
                secModels.addSecurityModel(usm);
            }
            /*snmp.getUSM().addUser(
                    new OctetString(username),
                    new OctetString(enginId),
                    new UsmUser(new OctetString(username), AuthMD5.ID,
                            new OctetString(authPassword), Priv3DES.ID,
                            new OctetString(privPassword)));*/
            // add user to the USM
            snmp.getUSM().addUser(userName2,new OctetString(enginId),
                    new UsmUser(userName2,AuthMD5.ID,authPass,Priv3DES.ID,privPass)
            );

            target.setAddress(targetAddress);
            target.setRetries(2);
            target.setTimeout(3000);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_NOPRIV);
            target.setSecurityName(userName2);

            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.NOTIFICATION);
            VariableBinding v = new VariableBinding();
            v.setOid(SnmpConstants.sysName);
            v.setVariable(new OctetString("Snmp Trap V3 Test sendV3 AUTH_NOPRIV----------"));
            System.out.println("Snmp Trap V3 Test sendV3 AUTH_NOPRIV");
            pdu.add(v);

            snmp.setLocalEngine(enginId, 500, 1);
            ResponseEvent send = snmp.send(pdu, target);
            //System.out.println(send.getError());

            return send;
        }

    }
    /**
     * 测试SnmpV3  带认证协议，加密协议
     * @return
     * @throws IOException
     */
    public ResponseEvent sendV3AUTH_PRIV() throws IOException{
        OctetString userName3 = new OctetString(username3);
        OctetString authPass = new OctetString(authPassword);
        OctetString privPass = new OctetString(privPassword);

        TransportMapping transport;
        transport = new DefaultUdpTransportMapping();

        Snmp snmp = new Snmp(transport);
        //MPv3.setEnterpriseID(35904);
        USM usm = new USM(SecurityProtocols.getInstance(),
                new OctetString(MPv3.createLocalEngineID()), 500);
        SecurityModels.getInstance().addSecurityModel(usm);

        UserTarget target = new UserTarget();

        byte[] enginId = "JL-CC-SNL".getBytes();

        SecurityModels secModels = SecurityModels.getInstance();
        synchronized (secModels) {
            if (snmp.getUSM() == null) {
                secModels.addSecurityModel(usm);
            }
            /*snmp.getUSM().addUser(
                    new OctetString(username),
                    new OctetString(enginId),
                    new UsmUser(new OctetString(username), AuthMD5.ID,
                            new OctetString(authPassword), Priv3DES.ID,
                            new OctetString(privPassword)));*/
            // add user to the USM
            snmp.getUSM().addUser(userName3,new OctetString(enginId),
                    new UsmUser(userName3,AuthMD5.ID,authPass,Priv3DES.ID,privPass)
            );
            target.setAddress(targetAddress);
            target.setRetries(2);
            target.setTimeout(3000);
            target.setVersion(SnmpConstants.version3);
            target.setSecurityLevel(SecurityLevel.AUTH_PRIV);
            target.setSecurityName(userName3);

            ScopedPDU pdu = new ScopedPDU();
            pdu.setType(PDU.NOTIFICATION);
            VariableBinding v = new VariableBinding();
            v.setOid(SnmpConstants.sysName);
            v.setVariable(new OctetString("Snmp Trap V3 Test sendV3 AUTH_PRIV----------"));
            System.out.println("Snmp Trap V3 Test sendV3 AUTH_PRIV");
            pdu.add(v);

            snmp.setLocalEngine(enginId, 500, 1);
            ResponseEvent send = snmp.send(pdu, target);
            //System.out.println(send.getError());

            return send;
        }

    }



}

