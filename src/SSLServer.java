import javax.net.ssl.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.concurrent.*;

public class SSLServer implements Runnable {

    private final static int DEFAULTPORT = 2000;
    /**
     * Array that holds all messages to be sent to the different clients that is connected
     */
    private static CopyOnWriteArrayList<LinkedBlockingQueue<String>> clientMessageQueues;

    private final static Object lock = new Object();

    private final SSLSocket clientSocket;
    //private String clientName;
    private LinkedBlockingQueue<String> clientMessageQueue;

    private SSLServer(SSLSocket clientSocket, LinkedBlockingQueue<String> clientMessageQueue, CopyOnWriteArrayList<LinkedBlockingQueue<String>> clientMessageQueues) {
        this.clientSocket = clientSocket;
        this.clientMessageQueue = clientMessageQueue;
        SSLServer.clientMessageQueues = clientMessageQueues;
    }

    /**
     * Method to start when thread is started, server is a implements the runnable interface
     * The server start one new thread for each client that connects to the server
     */
    public void run() {
        SocketAddress remoteSocketAddress = clientSocket.getRemoteSocketAddress();
        SocketAddress localSocketAddress = clientSocket.getLocalSocketAddress();
        System.out.println("Accepted client " + remoteSocketAddress
                + " (" + localSocketAddress + ").");
        System.out.println("There is now: " + clientMessageQueues.size() + " clients connected to the server.");

        /**
         * Creates reader and writer for communication to and from the client
         */
        PrintWriter socketWriter = null;
        BufferedReader socketReader = null;

        try {
            socketWriter = new PrintWriter(clientSocket.getOutputStream(), true);
            PrintWriter finalSocketwriter = socketWriter;
            finalSocketwriter.println("TEst");
            /**
             * Creates a new thread that sends new messages to the client
             */
            new Thread(() -> {
                String mess;
                while (true) {
                    try {
                        /**
                         * wait for a new message to arrive in the clients messagequeue and the send it to the client
                         */
                        System.out.println("Stop");
                        mess = clientMessageQueue.take();
                        System.out.println("skickar till client in thread " + Thread.currentThread().getName() + " : " + mess);
                        finalSocketwriter.println(mess);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }).start();

            socketReader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String threadInfo = "(" + Thread.currentThread().getName() + ")";
            String inputLine = socketReader.readLine();
            System.out.println("Received: \"" + inputLine + "\" from" + remoteSocketAddress + threadInfo);

            String clientName = inputLine;

            while (inputLine != null) {
                synchronized (lock) {
                    for (LinkedBlockingQueue<String> que : clientMessageQueues) {
                        if(que != clientMessageQueue) {
                            que.put(clientName + ": " + inputLine);
                        }
                    }
                }
                Thread.sleep(100);
                try {
                    inputLine = socketReader.readLine();
                }catch (SocketException e){
//                    System.out.println("Client disconnected!");
//                    System.out.println("There is now: " + clientMessageQueues.size() + " clients connected to the server.");
                    break;
                }
                //System.out.println("Received: \"" + inputLine + "\" from " + clientName + " " + remoteSocketAddress +threadInfo);
            }
            System.out.println("Closing connection " + remoteSocketAddress + " (" + localSocketAddress + ").");
        }catch (SocketException e){

        }
        catch (IOException | InterruptedException e) {
            System.out.println("IO EXCEPTION");
            e.printStackTrace();
        } finally {
            System.out.println("Client disconnected!");
            clientMessageQueues.remove(clientMessageQueue);
            System.out.println("There is now: " + clientMessageQueues.size() + " clients connected to the server.");
            try {
                if (socketWriter != null)
                    socketWriter.close();
                if (socketReader != null)
                    socketReader.close();
                if (clientSocket != null)
                    clientSocket.close();
            } catch (Exception exception) {
                System.out.println(exception);
            }
        }
    }

    public static void main(String[] args) {
        System.out.println("Server started!");

        /**
         * Creates Sockets for server and client connections
         */
        SSLServerSocket sslServerSocket = null;
        SSLSocket sslclientSocket = null;
        SSLServerSocketFactory sslServerSocketFactory = null;

        /**
         * Sets port to argument received or as DEFAULTPORT
         */
        int port;
        if (args.length == 1) {
            port = Integer.parseInt(args[0]);
        } else {
            port = DEFAULTPORT;
        }

        try {
            /**
             * start the server on Port:port
             */

            /////////////////////////////////////
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance("JKS");
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
            InputStream ksIs = new FileInputStream("keystore");
            try {
                try {
                    ks.load(ksIs, "password".toCharArray());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (CertificateException e) {
                    e.printStackTrace();
                }
            } finally {
                if (ksIs != null) {
                    ksIs.close();
                }
            }

            KeyManagerFactory kmf = null;
            try {
                kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                        .getDefaultAlgorithm());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            try {
                kmf.init(ks, "password".toCharArray());
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            }

            //////////////////////////////////////
            System.setProperty("javax.net.ssl.keyStore", "./keystore");
            System.setProperty("javax.net.ssl.keyStorePassword", "password");
            java.lang.System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                    new X509TrustManager() {
                        public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {
                        }

                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }
                    }
            };

            // Install the all-trusting trust manager
            SSLContext sc = null;
            try {
                sc = SSLContext.getInstance("TLSv1.2");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            try {
                sc.init(kmf.getKeyManagers(), null,  null);
            } catch (KeyManagementException e) {
                e.printStackTrace();
            }


            /////////////////////////////////////

            System.setProperty("jdk.tls.server.protocols", "TLSv1.2");
            sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

            sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port);
            sslServerSocket.setNeedClientAuth(false);
            //sslServerSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
            sslServerSocket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"});

            String[] chiperSuites = sslServerSocket.getEnabledCipherSuites();
            String[] updatedChiperSuits = new String[chiperSuites.length + 1];
            for(byte b = 0; b < chiperSuites.length; b++){
                updatedChiperSuits[b] = chiperSuites[b];
            }
            updatedChiperSuits[chiperSuites.length] = "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
            sslServerSocket.setEnabledCipherSuites(updatedChiperSuits);


            //sslServerSocket.setEnabledCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});

            SocketAddress serverSocketAdress = sslServerSocket.getLocalSocketAddress();
            System.out.println("Listening (" + serverSocketAdress + ")");
            CopyOnWriteArrayList<LinkedBlockingQueue<String>> clientMessageQueues = new CopyOnWriteArrayList<>();
            LinkedBlockingQueue<String> messages = new LinkedBlockingQueue<>();

            /**
             * wait for incoming connections from clients and spawn a new thread for each client
             * and waits for the next client to connect
             */
            while(true){
                System.setProperty("jdk.tls.server.protocols", "TLSv1.2");
                sslclientSocket = (SSLSocket) sslServerSocket.accept();
                System.out.println("CLIENT CONNECTED!");

               String[] clientChiperSuites = sslclientSocket.getEnabledCipherSuites();
               String[] clientUpdatedChiperSuits = new String[clientChiperSuites.length + 1];
                for(byte b = 0; b < clientChiperSuites.length; b++){
                    clientUpdatedChiperSuits[b] = clientChiperSuites[b];
                }
                clientUpdatedChiperSuits[clientChiperSuites.length] = "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
                sslclientSocket.setEnabledCipherSuites(clientUpdatedChiperSuits);

              //  sslclientSocket.setEnabledCipherSuites(new String[] {"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA"});

                sslclientSocket.setEnabledProtocols(new String[]{"TLSv1.2"});


                LinkedBlockingQueue<String> clientMessageQueue = new LinkedBlockingQueue<>();
                clientMessageQueues.add(clientMessageQueue);
                //System.out.println("There is now: " + clientMessageQueues.size() + " clients connected to the server.");
                SSLServer server = new SSLServer(sslclientSocket, clientMessageQueue, clientMessageQueues);
                Thread thread = new Thread(server);
                thread.start();
                //executor.execute(new Server(sslclientSocket, clientMessageQueue, clientMessageQueues));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            /**
             * Close the socket that is waiting for clients
             */
            try {
                if(sslServerSocket != null){
                    sslServerSocket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
