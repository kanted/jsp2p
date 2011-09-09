package it.saccosilvestri.jsp2p.securecommunication;

import it.saccosilvestri.jsp2p.exceptions.BadHashCodeException;
import it.saccosilvestri.jsp2p.exceptions.BadNonceException;
import it.saccosilvestri.jsp2p.exceptions.UnreachableLoggerConfigurationFileException;
import it.saccosilvestri.jsp2p.logging.LogManager;
import it.saccosilvestri.jsp2p.protocol.AliceProtocol;
import it.saccosilvestri.jsp2p.protocol.BobProtocol;
import it.saccosilvestri.jsp2p.utility.ByteArrayUtility;
import it.saccosilvestri.jsp2p.utility.CertificateUtility;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
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

/**
* @brief Maschera all'utente il protocollo di scambio della chiave di sessione.
* @author Sacco Cosimo & Silvestri Davide
*/

public class SecureCommunication {

	private Socket clientSocket;
	private InputStream in;
	private OutputStream out;
	private Cipher cipher;
	private SecretKeySpec sessionKey;

	/**
	 * Invia un array di byte.
	 * Lo scambio dei messaggi del protocollo e l'utilizzo della chiave di sessione 
	 * vengono resi trasparenti per l'utente attraverso l'utilizzo di questo metodo.
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public void send(byte[] messageToBeSent) throws InvalidKeyException,
			IOException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
		LogManager.currentLogger.info("Calculating message hash...");
		byte[] message = appendHash(messageToBeSent);
		cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
		LogManager.currentLogger.info("Encrypting with session key...");
		byte[] ciphredText = cipher.doFinal(message);
		byte length = (new Integer(ciphredText.length)).byteValue();
		LogManager.currentLogger.info("Sending message...");
		out.write(length);
		out.write(ciphredText);
		out.flush();
	}

	/**
	 * Riceve un array di byte.
	 * Lo scambio dei messaggi del protocollo e l'utilizzo della chiave di sessione 
	 * vengono resi trasparenti all'utente attraverso l'utilizzo di questo metodo.
	 * @throws BadHashCodeException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public byte[] receive() throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchProviderException, BadHashCodeException {
		cipher.init(Cipher.DECRYPT_MODE, sessionKey);
		byte[] lengthBytes = new byte[4];
		in.read(lengthBytes, 0, 1);
		LogManager.currentLogger.info("Receiving message...");
		int length = ByteArrayUtility.byteArrayToInt(lengthBytes);
		byte[] ciphredText = new byte[length];
		in.read(ciphredText, 0, length);
		LogManager.currentLogger.info("Decrypting with session key...");
		byte[] messageReceived = cipher.doFinal(ciphredText);
		LogManager.currentLogger.info("Checking hash...");
		byte[] message = checkHash(messageReceived);
		return message;
	}

	/**
	 * Aggiunge l'hash del messaggio in coda al messaggio stesso.
	 * Messaggio ed hash sono divisi da un opportuno separatore.
	 */
	public byte[] appendHash(byte[] messageToBeSent) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
		MessageDigest sha = MessageDigest.getInstance("SHA-1", "BC");
		byte[] hash  = sha.digest(messageToBeSent);
		byte[] message = new byte[messageToBeSent.length + hash.length];
		System.arraycopy(messageToBeSent, 0, message, 0, messageToBeSent.length);
		System.arraycopy(hash, 0, message, messageToBeSent.length, hash.length);
		return message;
	}
	
	/**
	 * Controlla che l'hash in coda al messaggio 
	 * corrisponda all'hash del messaggio stesso.
	 */
	public byte[] checkHash(byte[] messageReceived) throws NoSuchAlgorithmException, NoSuchProviderException, BadHashCodeException, UnsupportedEncodingException {
		MessageDigest sha = MessageDigest.getInstance("SHA-1", "BC");
		byte[] message = new byte[messageReceived.length - 16];
		System.arraycopy(messageReceived, 0, message, 0, messageReceived.length - 16);
		byte[] digesta  = sha.digest(message);
		byte[] digestb = new byte [16];
		System.arraycopy(messageReceived, messageReceived.length - 16, digestb, 0, 16);
		if(!MessageDigest.isEqual(digesta, digestb))
			throw new BadHashCodeException();
		return message;
	}
	
	
	/**
	 * Il costruttore inizializza il logger ed esegue la parte
	 * di protocollo che gli compete decidendo in base al valore del 
	 * booleano passive.
	 */
	public SecureCommunication(boolean passive, Socket socket, KeyPair keyPair,
			X509Certificate peerCertificate, X509Certificate CACert, String peerName)
			throws InvalidKeyException, CertificateException, SocketException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException, NoSuchPaddingException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidKeySpecException, IOException, BadNonceException, UnreachableLoggerConfigurationFileException {
		LogManager.initialization("logger.conf");
		LogManager.currentLogger.info("STARTING secure communication.");
		clientSocket = socket;
		in = clientSocket.getInputStream();
		out = clientSocket.getOutputStream();
		PublicKey CAPublicKey = CACert.getPublicKey();
		CertificateUtility.checkCertificate(CACert, CAPublicKey);
		if (!passive) {
			AliceProtocol ap = new AliceProtocol(clientSocket, keyPair,
					peerCertificate, CAPublicKey, peerName);
			sessionKey = ap.protocol();
		} else {
			BobProtocol bp = new BobProtocol(clientSocket, keyPair,
					peerCertificate, CAPublicKey, peerName);
			sessionKey = bp.protocol();
		}

		LogManager.currentLogger.info("Session key established.");
		LogManager.currentLogger.info("Creating the CipherStream...");
		cipher = Cipher.getInstance("AES", "BC");

	}

}
