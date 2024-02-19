package com.ssl.q2.test;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class SSLClient {

// config vm run .java output verbose log : -Djavax.net.debug=all

    private static Logger logger = new Logger();
    private static String protocol = "TLS";
    private static char[] keyPass = "123456".toCharArray();
    private static String host = "192.168.202.59";

    public static void main(String[] args) throws Exception {
        String charset = "utf-8";
        int port = 8080;
        String msg = "hello ssl";
        BufferedReader reader = null;
        BufferedWriter writer = null;
        SSLSocketFactory ssf = createSocketFactory();
        SSLSocket socket = (SSLSocket) ssf.createSocket(host, port);
        socket.setSoTimeout(10000);
//        msg = socket.getNeedClientAuth() + " ";
        // write content
        writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), charset));
        logger.info("send data to {" + host + "}:{" + port + "}" + "msg:" + msg);
        writer.write(msg + "\n\n");
        writer.flush();// handshake
        // wait read response
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), charset));
        logger.info("already receiver");
        char[] chars = new char[5000];
        int read = reader.read(chars);
        String result = new String(chars);
        logger.info(read + "receiver response ：" + result);
    }

    public static SSLSocketFactory createSocketFactory() throws Exception {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("client.p12"), keyPass);//client cert path keystore, password
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, keyPass);
        //client.truststore contains server cert
        KeyStore ts = KeyStore.getInstance("JKS");
        ts.load(new FileInputStream("client.truststore"), keyPass);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        SSLContext ctx = SSLContext.getInstance(protocol);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx.getSocketFactory();
    }
}