package com.wangxc.snmpdemo;

import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.PDU;

/**
 * @ClassName Test
 * @Description TODO
 * @Author wangxc
 * @date 2022/7/21 14:52
 * @Version 1.0
 */
public class MyCommandResponder implements CommandResponder {

    @Override
    public void processPdu(CommandResponderEvent commandResponderEvent) {
        PDU pdu = commandResponderEvent.getPDU();

        if (pdu.getType() == PDU.V1TRAP) {

            System.out.println("receive V1 TRAP:");
            System.out.println(pdu);
        }

        if (pdu.getType() == PDU.TRAP) {
            System.out.println("receive V2/V3 TRAP");
            System.out.println(pdu);
        }

    }
}
