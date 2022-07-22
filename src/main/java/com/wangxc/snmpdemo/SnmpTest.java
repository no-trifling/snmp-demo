package com.wangxc.snmpdemo;

import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


/**
 * @ClassName SnmpTest
 * @Description 发送SNMPNEXT请求
 * @Author wangxc
 * @date 2022/7/13 17:19
 * @Version 1.0
 */
public class SnmpTest {

    public static void main(String[] args) throws IOException {


//        UdpAddress udpAddress = new UdpAddress("127.0.0.1/162");
        UdpAddress udpAddress = new UdpAddress("39.105.213.2/162");
        String username = "wangxc";
        String authenticationPassphrase = "mypassword";
        String privacyPassphrase = "mypassword";
        byte[] engineId = "JL-CC-SNL".getBytes();

        List<VariableBinding> variableBindings = new ArrayList<>();
        variableBindings.add(new VariableBinding(SnmpConstants.snmpTrapOID, HwAlarmOidConstants.iMAPNorthboundFaultAlarmReportNotificationType));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmCSN, new OctetString("2000143")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmCategory, new OctetString("1")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmOccurTime, new OctetString("2016-11-22 00:35:00")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmMOName, new OctetString("MyDevice 10.137.63.119")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmProductID, new Integer32(5)));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmNEType, new OctetString("RH2288H V3")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmNEDevID, new OctetString("NE=34603236")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmDevCsn, new OctetString("550142")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmID, new Integer32(1100138)));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmType, new Integer32(1)));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmLevel, new Integer32(1)));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmRestore, new Integer32(2)));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmConfirm, new Integer32(2)));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmAckTime, new OctetString("")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmRestoreTime, new OctetString("")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmOperator, new OctetString("")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.IMAPNorthboundAlarmParas1, new OctetString("278413609")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmExtendInfo, new OctetString("Address=10.137.63.227, Protocol=SNMP, Port=161")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmProbablecause, new OctetString("Registration failure of the trap IP address with the device")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmProposedrepairactions, new OctetString("2000143")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmSpecificproblems, new OctetString("Possible causes: The number of trap IP addresses registered on the device reached the upper limit")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmClearOperator, new OctetString("")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmObjectInstanceType, new OctetString("Interface")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmClearCategory, new OctetString("0")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmServiceAffectFlag, new OctetString("1")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.iMAPNorthboundAlarmAdditionalInfo, new OctetString("Recommended actions:Contact your service provider to clear the alarm.Failed to register a trap IP address with the device. The target IP address is (10.137.67.83) and the target port is (162).")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.IMAPNorthboundAlarmExtendProductItem1, new OctetString("10.10.10.10")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.IMAPNorthboundAlarmExtendProductItem5, new OctetString("NE=34603236")));
        variableBindings.add(new VariableBinding(HwAlarmOidConstants.IMAPNorthboundAlarmExtendProductItem6, new OctetString("MyDevice 10.137.63.119")));


        SnmpTrap.v3(udpAddress, username, AuthMD5.ID, authenticationPassphrase, PrivDES.ID, privacyPassphrase, engineId, variableBindings);



    }

    /**
     * Hex字符串转byte
     * @param inHex 待转换的Hex字符串
     * @return  转换后的byte
     */
    public static byte hexToByte(String inHex){
        return (byte)Integer.parseInt(inHex,16);
    }


    /**
     * hex字符串转byte数组
     * @param inHex 待转换的Hex字符串
     * @return  转换后的byte数组结果
     */
    public static byte[] hexToByteArray(String inHex){
        int hexlen = inHex.length();
        byte[] result;
        if (hexlen % 2 == 1){
            //奇数
            hexlen++;
            result = new byte[(hexlen/2)];
            inHex="0"+inHex;
        }else {
            //偶数
            result = new byte[(hexlen/2)];
        }
        int j=0;
        for (int i = 0; i < hexlen; i+=2){
            result[j]=hexToByte(inHex.substring(i,i+2));
            j++;
        }
        return result;
    }



}
