package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

/**
 * @ClassName SnmpTest
 * @Description 发送SNMPNEXT请求
 * @Author wangxc
 * @date 2022/7/13 17:19
 * @Version 1.0
 */
public class SnmpTest {

    public static void main(String[] args) throws IOException {

        byte[] addr = {39, 105, (byte) 213, 2};
        int address  = addr[3] & 0xFF;
        address |= ((addr[2] << 8) & 0xFF00);
        address |= ((addr[1] << 16) & 0xFF0000);
        address |= ((addr[0] << 24) & 0xFF000000);
        System.out.println(address);
        System.out.println(Integer.toBinaryString(39) + "." + Integer.toBinaryString(105) + "." + Integer.toBinaryString(213) + "." + Integer.toBinaryString(2));
        System.out.println(Integer.toBinaryString(address));

    }



}
