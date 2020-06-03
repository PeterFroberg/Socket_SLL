import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.Socket;
import java.net.SocketAddress;

public class SSLClient implements Runnable {
    /**
     * Sets default Host address and port
     */
    private final static String DEFAULTHOST = "127.0.0.1";
    private final static int DEFAULTPORT = 2000;

    private final BufferedReader socketReader;

    private SSLClient(BufferedReader socketReader) {
        this.socketReader = socketReader;
    }

    /**
     * starts a receiver thread for the client
     */
    public void run() {
        try {
            /**
             * Keeps the receiver alive for the client
             */
            while (true) {
                if (socketReader.ready()) {
                    String line = socketReader.readLine();
                    System.out.println(line);
                }
                Thread.sleep(100);
            }
        } catch (InterruptedException e) {

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {

        String host;
        int port;
        System.out.println("Client started");

        /**
         * Creating connection to remote server
         */
        SSLSocket sslSocket = null;
        PrintWriter socketWriter = null;
        BufferedReader socketReader = null;
        BufferedReader consoleReader = null;
        SSLSocketFactory sslSocketFactory = null;


        try {
            /**
             * Parse start arguments for host and port if arguments are missing sets default values
             */
            if (args.length >= 1) {
                host = args[0];
                if (args.length == 2) {
                    port = Integer.parseInt(args[1]);
                } else {
                    port = DEFAULTPORT;
                }
            } else {
                host = DEFAULTHOST;
                port = DEFAULTPORT;
            }

            /**
             * connects to the server on address:host and port:port
             */
            /////////////////////////////
            System.setProperty("javax.net.ssl.trustStore","./keystore");
            System.setProperty("javax.net.ssl.trustStorePassword", "password");


            /////////////////////////////



            System.setProperty("jdk.tls.server.protocols", "TLSv1.2");
            sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            sslSocket = (SSLSocket) sslSocketFactory.createSocket(host, port);
            sslSocket.setNeedClientAuth(false);
            sslSocket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"});

            sslSocket.setKeepAlive(true);
            sslSocket.setUseClientMode(true);
            sslSocket.startHandshake();

            String[] chiperSuites = sslSocket.getEnabledCipherSuites();
            String[] updatedChiperSuits = new String[chiperSuites.length + 1];
            for(byte b = 0; b < chiperSuites.length; b++){
                updatedChiperSuits[b] = chiperSuites[b];
            }
            updatedChiperSuits[chiperSuites.length] = "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
            sslSocket.setEnabledCipherSuites(updatedChiperSuits);


            //sslSocket.setEnabledCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});

            SocketAddress remoteSocketAddress = sslSocket.getRemoteSocketAddress();
            System.out.println("Connected to server" + remoteSocketAddress);

            socketWriter = new PrintWriter(sslSocket.getOutputStream(), true);
            socketReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));


            /**
             * Creates a sending thread
             */
            Thread sendThread = new Thread(new SSLClient(socketReader));
            sendThread.start();

            /**
             * sending messages
             */
            consoleReader = new BufferedReader(new InputStreamReader(System.in));
            String message = consoleReader.readLine();
            while (message != null && !message.equals("close")) {
                if (message != null && !message.isEmpty()) {
                    socketWriter.println(message);
                }
                message = consoleReader.readLine();
            }

            /**
             * Ends
             */
            sendThread.interrupt();
            sendThread.join();
            System.out.println("Closing connection to server:" + remoteSocketAddress);

            /**
             * catch if there is no server response when connecting
             */
        } catch (ConnectException e) {
            System.out.println("No server available!");
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

        /**
         * Closes all opened connections and sockets
         */ finally {
            try {
                if (socketWriter != null) {
                    socketWriter.close();
                }
                if (socketReader != null) {
                    socketReader.close();
                }
                if (sslSocket != null) {
                    sslSocket.close();
                }
                if (consoleReader != null) {
                    consoleReader.close();
                }

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
