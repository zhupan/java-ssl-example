package com.github.ssl;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;

/***********************************************************************************************************************
 * http://www.blogjava.net/stone2083/archive/2007/12/20/169015.html
 * <ul>
 * <li>1)生成服务端私钥</li>
 * <li>keytool -genkey -alias serverkey -keystore kserver.jks</li>
 * <li>2)根据私钥,到处服务端证书</li>
 * <li>keytool -exoport -alias serverkey -keystore kserver.jks -file server.crt</li>
 * <li>3)把证书加入到客户端受信任的keystore中</li>
 * <li>keytool -import -alias serverkey -file server.crt -keystore tclient.jks</li>
 * </ul>
 *
 * openssl x509 -outform der -in foo.pem -out foo.der
 **********************************************************************************************************************/

public class SSLServer {

    private static final int DEFAULT_PORT = 7777;

    private static final String SERVER_KEY_STORE_PASSWORD = "123456";
    private static final String SERVER_TRUST_KEY_STORE_PASSWORD = "123456";

    private SSLServerSocket serverSocket;

    public static void main(String[] args) {
        SSLServer server = new SSLServer();
        server.init();
        server.start();
    }

    /**
     * <ul>
     * <li>听SSL Server Socket</li>
     * <li> 由于该程序不是演示Socket监听，所以简单采用单线程形式，并且仅仅接受客户端的消息，并且返回客户端指定消息</li>
     * </ul>
     */
    public void start() {
        if (serverSocket == null) {
            System.out.println("ERROR");
            return;
        }
        while (true) {
            try {
                Socket socket = serverSocket.accept();
                InputStream inputStream = socket.getInputStream();
                OutputStream outputStream = socket.getOutputStream();

                BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(outputStream);

                byte[] buffer = new byte[20];
                bufferedInputStream.read(buffer);
                System.out.println(new String(buffer));

                bufferedOutputStream.write("Server Echo".getBytes());
                bufferedOutputStream.flush();

                socket.close();
            } catch (Exception e) {
                System.out.println(e);
            }
        }
    }

    /**
     * <ul>
     * <li>ssl连接的重点:</li>
     * <li>初始化SSLServerSocket</li>
     * <li>导入服务端私钥KeyStore，导入服务端受信任的KeyStore(客户端的证书)</li>
     * </ul>
     */
    public void init() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            KeyStore keyStore = KeyStore.getInstance("JKS");
            KeyStore trustKeyStore = KeyStore.getInstance("JKS");

            keyStore.load(new FileInputStream("data/kserver.jks"), SERVER_KEY_STORE_PASSWORD.toCharArray());
            trustKeyStore.load(new FileInputStream("data/tserver.jks"), SERVER_TRUST_KEY_STORE_PASSWORD.toCharArray());

            keyManagerFactory.init(keyStore, SERVER_KEY_STORE_PASSWORD.toCharArray());
            trustManagerFactory.init(trustKeyStore);

            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            serverSocket = (SSLServerSocket) sslContext.getServerSocketFactory().createServerSocket(DEFAULT_PORT);
            serverSocket.setNeedClientAuth(true);
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
