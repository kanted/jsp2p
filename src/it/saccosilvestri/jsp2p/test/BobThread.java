package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;

import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class BobThread extends Thread {

	Socket mySocket;
	private boolean passive;
	private int port;
	private String caPath;
	private String myPath;
	private KeyPair kp;

	public BobThread(String myPath, String caPath, int port, boolean passive,
			KeyPair kp) {
		this.passive = passive;
		this.caPath = caPath;
		this.kp = kp;
		this.myPath = myPath;
		this.port = port;
		this.start();
	}

	public void run() {
		try {
			
			System.out.println("***TEST THREAD***");
			if (passive) {
				ServerSocket server = new ServerSocket(port);
				mySocket = server.accept();
			} else
				mySocket = new Socket("127.0.0.1", port);
			System.out.println("****TUTTO FATTO****");
			FileInputStream f = new FileInputStream(caPath);
			CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
			X509Certificate caCert = (X509Certificate) fact.generateCertificate(f);
			f = new FileInputStream(myPath);
			X509Certificate peerCert = (X509Certificate) fact
					.generateCertificate(f);
			SecureCommunication peer = new SecureCommunication(passive, mySocket, kp, peerCert, caCert);
			
			System.out.println("Starting thread");
			byte[] b = {};
			String command = "";
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
