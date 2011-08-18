package it.saccosilvestri.jsp2p.peer;

import it.saccosilvestri.jsp2p.protocol.AliceProtocol;
import it.saccosilvestri.jsp2p.protocol.BobProtocol;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

public class Peer {
	
	private Socket clientSocket;
	private Cipher cipher;
	private Key sessionKey;

	public void send(byte[] messageToBeSent) throws InvalidKeyException {

		cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
	}

	public byte[] receive() throws InvalidKeyException {
		cipher.init(Cipher.DECRYPT_MODE, sessionKey);
		return null;

	}

	public Peer(boolean passive, Socket socket) {
		clientSocket = socket;
		if(!passive){
			AliceProtocol ap = new AliceProtocol(clientSocket);
			sessionKey = ap.doService();
		}
		else{
			BobProtocol bp = new BobProtocol(clientSocket);
			sessionKey = bp.doService();
		}
		// Create the CipherStream to be used
		System.out.println("Creating the CipherStream...");
		cipher = Cipher.getInstance("TripleDES/ECB/PKCS1Padding",
				"BC");

	}
}
