package it.saccosilvestri.jsp2p.protocol;

import it.saccosilvestri.jsp2p.utility.ByteArrayUtility;
import it.saccosilvestri.jsp2p.utility.CertificateUtility;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

abstract class Protocol {

	private Socket clientSocket;
	private KeyPair keyPair;
	private X509Certificate cert;
	private PublicKey caPublicKey;
	protected String peerName;
	private InputStream in;
	private OutputStream out;

	public Protocol(Socket cs, KeyPair kp, X509Certificate c, PublicKey capk,
			String pn) throws IOException {
		clientSocket = cs;
		keyPair = kp;
		cert = c;
		caPublicKey = capk;
		in = clientSocket.getInputStream();
		out = clientSocket.getOutputStream();
		peerName = pn;
	}

	protected void sendMyCertificate() throws IOException,
			CertificateEncodingException {
		byte[] certBytes = cert.getEncoded();
		out.write(certBytes);
		out.flush();
	}

	protected PublicKey receiveAndCheckCertificate()
			throws CertificateException, NoSuchProviderException,
			InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate retrievedCert = (X509Certificate) fact
				.generateCertificate(in);
		CertificateUtility.checkCertificate(retrievedCert, caPublicKey);
		return retrievedCert.getPublicKey();
	}

	protected PublicKey receiveAndCheckCertificateWithNameAuthentication(
			String peerName) throws CertificateException, NoSuchProviderException,
			InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate retrievedCert = (X509Certificate) fact
				.generateCertificate(in);
		CertificateUtility.checkCertificateWithNameAuthentication(retrievedCert,
				caPublicKey, peerName);
		return retrievedCert.getPublicKey();
	}

	protected void send(byte[] toSend) throws IOException {
		byte length = (new Integer(toSend.length)).byteValue();
		out.write(length);
		out.write(toSend);
		out.flush();
	}

	protected byte[] readNonce() throws IOException {
		byte[] lengthBytes = new byte[1];
		in.read(lengthBytes, 0, 1);
		int nonceLength = ByteArrayUtility.byteArrayToInt(lengthBytes);
		byte[] nonce = new byte[nonceLength];
		in.read(nonce, 0, nonceLength);
		return nonce;
	}

	protected Key getPrivate() {
		return keyPair.getPrivate();
	}

	protected SecretKeySpec sessionKey(byte[] nonceA, byte[] nonceB)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		byte[] key = new byte[nonceA.length + nonceB.length];
		System.arraycopy(nonceA, 0, key, 0, nonceA.length);
		System.arraycopy(nonceB, 0, key, nonceA.length, nonceB.length);
		MessageDigest sha = MessageDigest.getInstance("SHA-1", "BC");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit
		return new SecretKeySpec(key, "AES");

	}

}
