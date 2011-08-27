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
			
			SecureCommunication peer;
			String command = new String();
			System.out.println("Sintassi per inviare un messaggio:");
			System.out.println("send [messagge] to [ip:port]");
			while (command != "quit") {
				
				byte[] b = new byte[128];
				System.in.read(b);

				command = new String(b, "US-ASCII");

				if (command.startsWith("send")&&command.contains("to")) {
					int toIndex = command.indexOf("to");
					String message = command.substring(4, toIndex);
					String indirizzo = command.substring(toIndex, command.length());
					int colonIndex = indirizzo.indexOf(":");
					String ip = indirizzo.substring(0,colonIndex);
					int port = Integer.parseInt(indirizzo.substring(colonIndex,indirizzo.length()));
					mySocket = new Socket(ip, port);
					peer = new SecureCommunication(false, mySocket, kp, peerCert, caCert);
					peer.send(message.getBytes());
				} if(command.startsWith("help")){	
					System.out.println("---HELP---");
					System.out.println("To exit type 'quit'");
					System.out.println("Sintassi per inviare un messaggio:");
					System.out.println("send [messagge] to [ip:port]");
					System.out.println("---END---");
				}
				else
					System.out.println("Unknown command.");
			}

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}

}
