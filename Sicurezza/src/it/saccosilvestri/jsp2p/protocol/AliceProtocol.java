package it.saccosilvestri.jsp2p.protocol;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AliceProtocol extends Protocol{


	public AliceProtocol(Socket cs, KeyPair kp, X509Certificate c,
			PublicKey capk) throws IOException {
		super(cs,kp,c,capk);
	}
	

	public SecretKeySpec protocol() throws CertificateException, IOException,
			SocketException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, BadNonceException, InvalidKeySpecException {

		System.out.println("A");

		// (1) Invio del certificato del peer
		sendMyCertificate();
		System.out.println("A ha inviato il certificato...");
		
		// (2) Ricezione del certificato del peer, verifica ed estrazione della
		// chiave pubblica.
		PublicKey pKey = receiveCertificate();

		// (3) Invio di un nonce cifrato con pKey
		// Create a secure random number generator
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		// Get 1024 random bits
		byte[] nonceA = new byte[64];
		sr.nextBytes(nonceA);
		Cipher cipher = Cipher.getInstance("RSA", "BC");
		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		System.out.println("ALICE -- NA*******");
		byte[] cipherText  = cipher.doFinal(nonceA);
		System.out.println("LUNGHEZZA NA SU A"+cipherText.length);
		//TODO
		send(cipherText);
		System.out.println("ALICE -- NA+NB*******");
		
		// (4) Ricezione di (nA,nB) cifrati con la mia chiave pubblica
		System.out.println("ALICE -- ReadNa*******");
		byte[] nA = readNonce();
		System.out.println("ALICE -- ReadNb*******");
		byte[] nB = readNonce();
		System.out.println("ALICE -- QUINDI111*******");
		cipher.init(Cipher.DECRYPT_MODE, getPrivate());
		System.out.println("ALICE -- QUINDI222*******");
		byte[] plainText = cipher.doFinal(nA);
		System.out.println("ALICE -- CIFO*******");
		if (!Arrays.equals(plainText, nonceA))
			throw new BadNonceException();
		byte[] nonceB = cipher.doFinal(nB);
		
		// (5) Invio di nB cifrato con la chiave pubblica di B
		cipher.init(Cipher.ENCRYPT_MODE, pKey);
		byte[] ciphredB = cipher.doFinal(nonceB);
		send(ciphredB);

		closeStreams();
		
		//(6) Generazione chiave di sessione
		return sessionKey(nonceA, nonceB);

	}

}
