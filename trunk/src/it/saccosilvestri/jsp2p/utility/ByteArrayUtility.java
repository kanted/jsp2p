package it.saccosilvestri.jsp2p.utility;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.openssl.PEMWriter;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class ByteArrayUtility {

	/**
	 * Converte un array di byte nell'intero corrispondente.
	 */
	public static int byteArrayToInt(byte[] b) {
		int value = 0;
		for (int i = 0; i < b.length; i++) {
			value += b[i] * Math.pow(2, i);
		}
		if (value < 0)
			value = -value;
		return value;
	}

}
