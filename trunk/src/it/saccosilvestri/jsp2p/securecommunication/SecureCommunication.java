package it.saccosilvestri.jsp2p.securecommunication;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;
import it.saccosilvestri.jsp2p.protocol.AliceProtocol;
import it.saccosilvestri.jsp2p.protocol.BobProtocol;
import it.saccosilvestri.jsp2p.utility.ByteArrayUtility;
import it.saccosilvestri.jsp2p.utility.CertificateVerificationUtility;

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
import javax.crypto.spec.SecretKeySpec;

public class SecureCommunication {
	
	private Socket clientSocket;
	InputStream in;
	OutputStream out;
	private Cipher cipher;
	private SecretKeySpec sessionKeySpec;
	

	public void send(byte[] messageToBeSent) throws InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.ENCRYPT_MODE, sessionKeySpec);
		byte[] ciphredText = cipher.doFinal(messageToBeSent);
		byte length = (new Integer(ciphredText.length)).byteValue();
		out.write(length);
		out.write(ciphredText);
		out.flush();
	}

	public void receive(byte[] messageToBeReceived) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
		cipher.init(Cipher.DECRYPT_MODE, sessionKeySpec);
		byte[] lengthBytes = new byte[3]; //TODO per stare tranquilli
		in.read(lengthBytes,0,1);
		int length = ByteArrayUtility.byteArrayToInt(lengthBytes);
		byte[] ciphredText = new byte[length];
		in.read(ciphredText,0,length);
		messageToBeReceived = cipher.doFinal(ciphredText);
	}

	public SecureCommunication(boolean passive, Socket socket, KeyPair keyPair, X509Certificate peerCertificate, X509Certificate CACert) throws InvalidKeyException, CertificateException, SocketException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException, BadNonceException  {
		clientSocket = socket;
		in = clientSocket.getInputStream();
		out = clientSocket.getOutputStream();
		CertificateVerificationUtility.checkCertificate(CACert,CACert.getPublicKey());
		PublicKey CAPublicKey = CACert.getPublicKey();
		if(!passive){
			AliceProtocol ap = new AliceProtocol(clientSocket,keyPair,peerCertificate,CAPublicKey);
			sessionKeySpec = ap.doService();
		}
		else{
			BobProtocol bp = new BobProtocol(clientSocket,keyPair,peerCertificate,CAPublicKey);
			sessionKeySpec = bp.doService();
		}
		// Create the CipherStream to be used
		System.out.println("Creating the CipherStream...");
		cipher = Cipher.getInstance("AES","BC");

	}
	
}
