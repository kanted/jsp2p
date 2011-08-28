package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
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
			
			SecureCommunication sc;
			String command = new String();
			System.out.println("Sintassi per inviare un messaggio:");
			System.out.println("send [message] to [ip:port]");
			while (command != "quit") {
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
			    command = br.readLine();
				if (command.startsWith("send")&&command.contains("to")) { //TODO regular expression
					System.out.println("YES");
					int toIndex = command.indexOf("to");
					String message = command.substring(4, toIndex);
					String indirizzo = command.substring(toIndex+3);
					int colonIndex = indirizzo.indexOf(":");
					String ip = indirizzo.substring(0,colonIndex);
					String portString = indirizzo.substring(colonIndex+1);
					int port = Integer.parseInt(portString);
					System.out.println("ECCOLO");
					mySocket = new Socket(ip, port);
					sc = new SecureCommunication(false, mySocket, kp, peerCert, caCert);
					sc.send(message.getBytes());
				} if(command.startsWith("help")){	
					System.out.println("---HELP---");
					System.out.println("To exit type 'quit'");
					System.out.println("Sintassi per inviare un messaggio:");
					System.out.println("send [messagge] to [ip:port]");
					System.out.println("---END---");
				}
			}

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}

}
