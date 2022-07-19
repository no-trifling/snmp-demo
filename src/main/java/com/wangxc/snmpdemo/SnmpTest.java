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

/**
 * @ClassName SnmpTest
 * @Description 发送SNMPNEXT请求
 * @Author wangxc
 * @date 2022/7/13 17:19
 * @Version 1.0
 */
public class SnmpTest {

    public static void main(String[] args) throws IOException {

        byte[] localEngineID = MPv3.createLocalEngineID();
        System.out.println(localEngineID.length);
        System.out.println(Arrays.toString(localEngineID));

    }



}
