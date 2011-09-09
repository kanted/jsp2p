package it.saccosilvestri.jsp2p.protocol;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;
import it.saccosilvestri.jsp2p.logging.LogManager;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
* @brief Parte del protocollo che compete al peer che riceve una richiesta di comunicazione.
* @author Sacco Cosimo & Silvestri Davide
*/

public class BobProtocol extends Protocol {

	public BobProtocol(Socket cs, KeyPair kp, X509Certificate c,
			PublicKey capk, String peerName) throws IOException {
		super(cs, kp, c, capk, peerName); 
	}

	/**
     * Protocollo per lo scambio della chiave di sessione.
     */
	public SecretKeySpec protocol() throws CertificateException, IOException,
			SocketException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, BadNonceException, InvalidKeySpecException {

		// (1) Ricezione del certificato del peer, verifica ed estrazione della
		// chiave pubblica.
		PublicKey pKey = receiveAndCheckCertificateWithNameAuthentication(peerName);

		// (2) Invio del certificato del peer
		sendMyCertificate();
		LogManager.currentLogger.info("BOB -- Sending certificate...");

		// (3) Ricezione di nA
		LogManager.currentLogger.info("BOB -- Receiving nonce A");
		byte[] nA = readNonce();
		byte[] nonceA = new byte[64];
		Cipher cipher = Cipher.getInstance("RSA", "BC");
		cipher.init(Cipher.DECRYPT_MODE, getPrivate());
		nonceA = cipher.doFinal(nA);

		// (4) Invio di (nA,nB) cifrati con la chiave pubblica di A
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		LogManager.currentLogger.info("BOB -- Sending nonce A and nonce B");
		byte[] nonceB = new byte[64];
		sr.nextBytes(nonceB);
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		byte[] ciphredA = cipher.doFinal(nonceA);
		send(ciphredA);
		byte[] ciphredB = cipher.doFinal(nonceB);
		send(ciphredB);

		// (5) Ricezione e verifica di nB
		LogManager.currentLogger.info("BOB -- Receiving nonce B");
		byte[] nB = readNonce();
		cipher.init(Cipher.DECRYPT_MODE, getPrivate());
		byte[] plainText = cipher.doFinal(nB);
		if (!Arrays.equals(plainText, nonceB))
			throw new BadNonceException();

		// (6) Generazione chiave di sessione
		return sessionKey(nonceA, nonceB);

	}

}
