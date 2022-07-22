package com.wangxc.snmpdemo;

import org.snmp4j.util.ThreadPool;

/**
 * @ClassName Test
 * @Description TODO
 * @Author wangxc
 * @date 2022/7/21 17:18
 * @Version 1.0
 */
public class Test {

    public static void main(String[] args) {
        ThreadPool threadPool = ThreadPool.create("Trap", 10);

    }
}
