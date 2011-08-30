package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;
import it.saccosilvestri.jsp2p.utility.ByteArrayUtility;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author Sacco Cosimo & Silvestri Davide
 */

public class BobThread extends Thread {

	private Socket communicationSocket;
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
			SecureCommunication sc = null;
			ServerSocket server = new ServerSocket(port);
			while (true) {
				communicationSocket = server.accept();
				InputStream in = communicationSocket.getInputStream();
				byte[] lengthBytes = new byte[1];
				in.read(lengthBytes, 0, 1);
				int length = ByteArrayUtility.byteArrayToInt(lengthBytes);
				byte[] peerIndex = new byte[length];
				in.read(peerIndex, 0, length);
				String peerID = new String(peerIndex, "US-ASCII");
				String namePeer = "CN=Peer" + peerID;
				sc = new SecureCommunication(true, communicationSocket, kp,
						peerCert, caCert, namePeer);
				System.out.println("Session for receiving message from peer: " + peerID + " established.");
				while (true) {
					System.out.print(">>");
					byte[] b = sc.receive();
					String message = new String(b, "US-ASCII");
					if (message.equals("quit")) {
						break;
					}
					System.out.println("Message received: " + message);
				}
				System.out.println("Disconnected.");
				System.out.print(">>");
			}
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - "
					+ e.getMessage());
		}
	}
}
