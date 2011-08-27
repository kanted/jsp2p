package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;

import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class AliceThread extends Thread {

	Socket mySocket;
	private int port;
	private X509Certificate peerCert;
	private X509Certificate caCert;
	private KeyPair kp;

	public AliceThread(X509Certificate peerCert, X509Certificate caCert , int port,
			KeyPair kp) {
		this.peerCert = peerCert;
		this.caCert = caCert;
		this.kp = kp;
		this.port = port;
		this.start();
	}

	public void run() {
		try {

			mySocket = new Socket("127.0.0.1", port);
			SecureCommunication peer = new SecureCommunication(false, mySocket, kp, peerCert, caCert);
			byte[] b = new byte[128];
			String command = "";
			System.out.println("Sintassi per inviare un messaggio:");
			System.out.println("send [messagge] to [ip:port]");
			while (command != "quit") {

				System.in.read(b);

				command = new String(b, "US-ASCII");

				if (command == "send") {
					System.in.read(b);
					peer.send(b);
				}
				
				if (command == "receive") {
					peer.receive(b);
					String app = new String(b, "US-ASCII");
					System.out.println(app);
				}
			}

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}

}
