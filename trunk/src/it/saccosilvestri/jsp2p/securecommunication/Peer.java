package it.saccosilvestri.jsp2p.securecommunication;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;
import it.saccosilvestri.jsp2p.protocol.AliceProtocol;
import it.saccosilvestri.jsp2p.protocol.BobProtocol;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class Peer {
	
	private Socket clientSocket;
	InputStream in;
	OutputStream out;
	private Cipher cipher;
	private Key sessionKey;
	

	public void send(byte[] messageToBeSent) throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
		byte[] ciphredText = cipher.doFinal(messageToBeSent);
		out.write(ciphredText);
	}

	public void receive(byte[] messageToBeReceived) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		cipher.init(Cipher.DECRYPT_MODE, sessionKey);
		byte[] ciphredText = {};
		in.read(ciphredText);
		messageToBeReceived = cipher.doFinal(ciphredText);
	}

	public Peer(boolean passive, Socket socket, KeyPair keyPair, X509Certificate peerCertificate, X509Certificate CACert) throws InvalidKeyException, CertificateException, SocketException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, BadNonceException {
		clientSocket = socket;
		in = clientSocket.getInputStream();
		out = clientSocket.getOutputStream();
		// Basic validation
		System.out.println("CA certificate:");
		System.out.println("Validating dates...");
		CACert.checkValidity(new Date());
		System.out.println("Verifying signature...");
		CACert.verify(CACert.getPublicKey());
		System.out.println("Dates and signature verified.");
		System.out.println("Retrieving PublicKey...");
		PublicKey CAPublicKey = CACert.getPublicKey();
		if(!passive){
			AliceProtocol ap = new AliceProtocol(clientSocket,keyPair,peerCertificate,CAPublicKey);
			sessionKey = ap.doService();
		}
		else{
			BobProtocol bp = new BobProtocol(clientSocket,keyPair,peerCertificate,CAPublicKey);
			sessionKey = bp.doService();
		}
		// Create the CipherStream to be used
		System.out.println("Creating the CipherStream...");
		cipher = Cipher.getInstance("TripleDES/ECB/PKCS1Padding",
				"BC");

	}
	
}
