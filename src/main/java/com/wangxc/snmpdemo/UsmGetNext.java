/*_############################################################################
  _##
  _##  SNMP4J - UsmGetNext.java
  _##
  _##  Copyright (C) 2019  Frank Fock (SNMP4J.org)
  _##
  _##  Licensed under the Apache License, Version 2.0 (the "License");
  _##  you may not use this file except in compliance with the License.
  _##  You may obtain a copy of the License at
  _##
  _##      http://www.apache.org/licenses/LICENSE-2.0
  _##
  _##  Unless required by applicable law or agreed to in writing, software
  _##  distributed under the License is distributed on an "AS IS" BASIS,
  _##  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  _##  See the License for the specific language governing permissions and
  _##  limitations under the License.
  _##
  _##########################################################################*/

package com.wangxc.snmpdemo;

import org.snmp4j.*;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.log.ConsoleLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.*;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class UsmGetNext {

    private Snmp snmp;
    private USM usm;

    public UsmGetNext() {
        ConsoleLogFactory consoleLogFactory = new ConsoleLogFactory();
        consoleLogFactory.getRootLogger().setLogLevel(LogLevel.DEBUG);
        LogFactory.setLogFactory(consoleLogFactory);
    }

    public void initSnmp() throws IOException {
        snmp = new Snmp();
        snmp.getMessageDispatcher().addCommandResponder(new CommandResponder() {
            @Override
            public void processPdu(CommandResponderEvent commandResponderEvent) {
                System.out.println(commandResponderEvent.toString());
            }
        });
        // Very important to add snmp as command responder which will finally process the PDU:
        snmp.getMessageDispatcher().addCommandResponder(snmp);

        snmp.addTransportMapping(new DefaultUdpTransportMapping(new UdpAddress(0)));
        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3());
        SecurityProtocols.getInstance().addDefaultProtocols();
        OctetString localEngineID = new OctetString(MPv3.createLocalEngineID());
        usm = new USM(SecurityProtocols.getInstance(), localEngineID, 0);
        usm.setEngineDiscoveryEnabled(true);
        SecurityModels.getInstance().addSecurityModel(usm);

        snmp.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm.getLocalEngineID().getValue()));
        snmp.listen();
    }

    public void next(String address, String contextName, String securityName,
                     String authPassphrase, String privPassphrase, String... oids) throws IOException {
        UsmUser usmUser = new UsmUser(new OctetString(securityName),
                AuthMD5.ID, new OctetString(authPassphrase),
                PrivDES.ID, new OctetString(privPassphrase));
        usm.addUser(usmUser);

        List<VariableBinding> oidList = new ArrayList<>(oids.length);
        for (String objectID : oids) {
            oidList.add(new VariableBinding(new OID(objectID)));
        }

        Address targetAddress = GenericAddress.parse(address);
        Target userTarget = new UserTarget();
        userTarget.setAddress(targetAddress);
        userTarget.setRetries(1);
        // set timeout to 500 milliseconds: 2*500ms = 1s total timeout
        userTarget.setTimeout(500);
        userTarget.setVersion(SnmpConstants.version3);
        userTarget.setSecurityLevel(SecurityLevel.AUTH_PRIV);
        userTarget.setSecurityName(usmUser.getSecurityName());

        ScopedPDU scopedPDU = new ScopedPDU();
        scopedPDU.addAll(oidList);
        scopedPDU.setContextName(new OctetString(contextName));
        ResponseListener responseListener = new ResponseListener() {
            @Override
            public synchronized void onResponse(ResponseEvent responseEvent) {
                // Free resources we will not wait for further events
                snmp.cancel(responseEvent.getRequest(), this);
                // Process response here:
                if (responseEvent.getResponse() != null) {
                    System.out.println("Received: "+responseEvent.getResponse());
                }
                else {
                    if (responseEvent.getError() != null) {
                        System.err.println("Error: "+responseEvent.getError());
                    }
                    else {
                        System.err.println("Timed out.");
                    }
                }
                notify();
            }
        };
        synchronized (responseListener) {
            snmp.getNext(scopedPDU, userTarget, null, responseListener);
            try {
                responseListener.wait(500000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * udp:39.105.213.2/161 testv3 mypassword mypassword .1.3.6.1.2.1.1.5.0
     * @param args
     */
    public static void main(String[] args) {
        if (args.length < 5) {
            System.out.println("Usage: UsmGetNext <address> <secName> <authPassphrase> <privPassphrase> <oid>...");
            System.out.println("where <address> is of the form 'udp:<hostname>/<port>'");
        }
        String targetAddress = args[0];
        String context = "";
        String securityName = args[1];
        String authPasssphrase = args[2];
        String privPasssphrase = args[3];
        String[] oids = new String[args.length - 4];
        System.arraycopy(args, 4, oids, 0, args.length - 4);
        UsmGetNext usmGetNext = new UsmGetNext();
        try {
            usmGetNext.initSnmp();
            usmGetNext.next(targetAddress, context, securityName, authPasssphrase, privPasssphrase, oids);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}