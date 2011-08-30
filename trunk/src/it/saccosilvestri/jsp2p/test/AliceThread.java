package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class AliceThread extends Thread {

	Socket mySocket;
	private String peerID;
	private int port;
	private X509Certificate peerCert;
	private X509Certificate caCert;
	private KeyPair kp;

	public AliceThread(String peerID, X509Certificate peerCert, X509Certificate caCert,
			int port, KeyPair kp) {
		this.peerID = peerID;
		this.peerCert = peerCert;
		this.caCert = caCert;
		this.kp = kp;
		this.port = port;
		this.start();
	}

	/**
	 * Accetta comandi per l'invio di messaggi ad altri peer.
	 * E' necessario specificare l'id del peer con cui si vuole instaurare una sessione
	 * (l'id verrˆ poi confrontato con quello presente nel certificato), l'ip e la porta
	 * su cui il peer e' in ascolto.
	 */
	public void run() {
		try {

			SecureCommunication sc = null;
			String command = new String();
			System.out.println("---LISTA DEI COMANDI---");
			System.out.println("Connessione ad un peer:");
			System.out.println("connect to [ip:port]");
			System.out.println("Inviare un messaggio al peer corrente:");
			System.out.println("send [message]");
			System.out.println("Disconnessione dal peer corrente:");
			System.out.println("disconnect");
			System.out.println("---FINE---");
			BufferedReader br = new BufferedReader(new InputStreamReader(
					System.in));
			while (true) {
				System.out.print(">>");
				command = br.readLine();
				if (command.startsWith("connect to")
						&& command.contains("@") && command.contains(":")) {
					int toIndex = command.indexOf("to");
					int atIndex = command.indexOf("@");
					String peerID = command.substring(toIndex + 3, atIndex);
					int numPeer = Integer.parseInt(peerID);
					String indirizzo = command.substring(atIndex + 1);
					int colonIndex = indirizzo.indexOf(":");
					String ip = indirizzo.substring(0, colonIndex);
					String portString = indirizzo.substring(colonIndex + 1);
					int port = Integer.parseInt(portString);
					mySocket = new Socket(ip, port);
					OutputStream out = mySocket.getOutputStream();
					byte[] peerIDToSend = peerID.getBytes();
					byte length = (new Integer(peerIDToSend.length)).byteValue();
					out.write(length);
					out.write(peerIDToSend);
					out.flush();
					String peerName = new String("CN=Peer" + numPeer);
					sc = new SecureCommunication(false, mySocket, kp, peerCert,
							caCert, peerName);
					System.out.println("Connesso al peer: "+numPeer);
				}
				else if (command.startsWith("send")){
					if(sc!=null){
					String message = command.substring(5);
					sc.send(message.getBytes());
					}
					else 
						System.out.println("Nessuna connessione attiva.");
				}
				else if (command.startsWith("disconnect")){
					if(sc!=null){
						sc.send("quit".getBytes());
						sc = null;
					}
					else 
						System.out.println("Nessuna connessione attiva.");
				}
				else if (command.startsWith("help")) {
					System.out.println("---HELP---");
					System.out.println("Connessione ad un peer:");
					System.out.println("connect to [ip:port]");
					System.out.println("Inviare un messaggio al peer corrente:");
					System.out.println("send [message]");
					System.out.println("Disconnessione dal peer corrente:");
					System.out.println("disconnect");
					System.out.println("---END---");
				}
				else {
					System.out.println("Comando non riconosciuto");
				}
			}

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - "
					+ e.getMessage());
		}
	}

}
