package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;

import java.io.FileInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class BobThread extends Thread {

	Socket mySocket;
	private int port;
	private X509Certificate peerCert;
	private X509Certificate caCert;
	private KeyPair kp;

	public BobThread(X509Certificate peerCert, X509Certificate caCert,
			int port, KeyPair kp) {
		this.peerCert = peerCert;
		this.caCert = caCert;
		this.kp = kp;
		this.port = port;
		this.start();
	}

	/**
	 * Riceve messaggi dagli altri peer.
	 */
	public void run() {
		try {
			ServerSocket server = new ServerSocket(port);
			while (true) {
				mySocket = server.accept();
				SecureCommunication sc = new SecureCommunication(true,
						mySocket, kp, peerCert, caCert, ""); // Per Bob non e' significativo l'identificatore del peer
				// perche' Bob non sa a priori da chi verra' contattato.
				System.out.println("Ricevendo...");
				byte[] b = sc.receive();
				System.out.print("Ricevuto: ");
				String app = new String(b, "US-ASCII");
				System.out.println(app);
				System.out.print(">>");
			}
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - "
					+ e.getMessage());
		}
	}
}
