package it.saccosilvestri.jsp2p.securecommunication;

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

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class SecureCommunication {

	private Socket clientSocket;
	InputStream in;
	OutputStream out;
	private Cipher cipher;
	private SecretKeySpec sessionKeySpec;

	/**
	 * Invia un array di byte.
	 * Lo scambio dei messaggi del protocollo e l'utilizzo della chiave di sessione 
	 * vengono resi trasparenti per l'utente che utilizza questo metodo per inviare bytes sul socket.
	 */
	public void send(byte[] messageToBeSent) throws InvalidKeyException,
			IOException, IllegalBlockSizeException, BadPaddingException {
		cipher.init(Cipher.ENCRYPT_MODE, sessionKeySpec);
		LogManager.currentLogger.info("Encrypting with session key...");
		byte[] ciphredText = cipher.doFinal(messageToBeSent);
		byte length = (new Integer(ciphredText.length)).byteValue();
		out.write(length);
		out.write(ciphredText);
		out.flush();
	}

	/**
	 * Riceve un array di byte.
	 * Lo scambio dei messaggi del protocollo e l'utilizzo della chiave di sessione 
	 * vengono resi trasparenti per l'utente che utilizza questo metodo per ricevere bytes sul socket.
	 */
	public byte[] receive() throws InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, IOException {
		cipher.init(Cipher.DECRYPT_MODE, sessionKeySpec);
		LogManager.currentLogger.info("Decrypting with session key...");
		byte[] lengthBytes = new byte[3]; // TODO per stare tranquilli
		in.read(lengthBytes, 0, 1);
		int length = ByteArrayUtility.byteArrayToInt(lengthBytes);
		byte[] ciphredText = new byte[length];
		in.read(ciphredText, 0, length);
		byte[] messageToBeReceived = cipher.doFinal(ciphredText);
		return messageToBeReceived;
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
			sessionKeySpec = ap.protocol();
		} else {
			BobProtocol bp = new BobProtocol(clientSocket, keyPair,
					peerCertificate, CAPublicKey, peerName);
			sessionKeySpec = bp.protocol();
		}

		LogManager.currentLogger.info("Session key established.");
		LogManager.currentLogger.info("Creating the CipherStream...");
		cipher = Cipher.getInstance("AES", "BC");

	}

}
