package com.wangxc.snmpdemo;

import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;

/**
 * @ClassName SnmpTest
 * @Description TODO
 * @Author wangxc
 * @date 2022/7/13 17:19
 * @Version 1.0
 */
public class SnmpTest {

    public ResponseListener myListener() {
        return new ResponseListener() {
            @Override
            public void onResponse(ResponseEvent responseEvent) {

            }
        };
    }
}
