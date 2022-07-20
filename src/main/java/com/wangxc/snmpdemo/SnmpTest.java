package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.Arrays;
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

        OctetString octetString = OctetString.fromHexString("80:00:00:00:01:02:03:04");
        System.out.println(Arrays.toString(octetString.toByteArray()));

        byte[] bytes = hexToByteArray("8000000001020304");
        System.out.println(Arrays.toString(bytes));

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
