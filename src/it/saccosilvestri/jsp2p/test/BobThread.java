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

	// private Socket mySocket;
	private int port;
	private X509Certificate peerCert;
	private X509Certificate caCert;
	private KeyPair kp;
	private CommunicationContainer cc;

	public BobThread(X509Certificate peerCert, X509Certificate caCert,
			int port, KeyPair kp, CommunicationContainer cc) {
		this.peerCert = peerCert;
		this.caCert = caCert;
		this.kp = kp;
		this.port = port;
		this.cc = cc;
		this.start();
	}

	/**
	 * Riceve messaggi dagli altri peer.
	 */
	public void run() {
		try {
			ServerSocket server = new ServerSocket(port);
			while (true) {
				if (cc.connected == false) {
					cc.communicationSocket = server.accept();
					InputStream in = cc.communicationSocket.getInputStream();
					byte[] lengthBytes = new byte[1];
					in.read(lengthBytes, 0, 1);
					int length = ByteArrayUtility.byteArrayToInt(lengthBytes);
					byte[] peerIndex = new byte[length];
					in.read(peerIndex, 0, length);
					String peerID = new String(peerIndex, "US-ASCII");
					String namePeer = "CN=Peer" + peerID;
					cc.sc = new SecureCommunication(true,
							cc.communicationSocket, kp, peerCert, caCert,
							namePeer);
					cc.connected = true;
					System.out.println("Connesso al peer: " + peerID);
				}
				System.out.print(">>");
				byte[] b = cc.sc.receive();
				String message = new String(b, "US-ASCII");
				if (message.equals("quit")) {
					break;
				}
				System.out.println("Ricevuto: " + message);
			}
			System.out.println("Disconnesso.");
			System.out.print(">>");
		} catch (SocketException e) {
			System.out.println(" Socket Exception - " + e.getMessage());
			cc.connected = false;
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - "
					+ e.getMessage());
		}
	}
}
