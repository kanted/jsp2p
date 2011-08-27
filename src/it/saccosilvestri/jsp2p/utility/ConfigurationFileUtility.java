package it.saccosilvestri.jsp2p.utility;

import it.saccosilvestri.jsp2p.exceptions.UnreachableCAConfigurationFileException;
import it.saccosilvestri.jsp2p.exceptions.WrongCAConfigurationFileSyntaxException;

import java.io.File;
import java.io.FileInputStream;
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
import java.util.Properties;

import org.bouncycastle.openssl.PEMWriter;

public class ConfigurationFileUtility {

	public static int retrieveNumPeer(String filename)
			throws UnreachableCAConfigurationFileException,
			FileNotFoundException, IOException,
			WrongCAConfigurationFileSyntaxException {

		String configurationFilePath = new String(filename);
		Properties configFile = new Properties();
		// Controllo che il file di configurazione esista e si possa aprire in
		// lettura.
		File file = new File(configurationFilePath);
		if (!file.canRead()) {
			throw new UnreachableCAConfigurationFileException();
		}
		configFile.load(new FileInputStream(configurationFilePath));
		try {
			return 2;
			//return Integer.parseInt(configFile.getProperty("NUM_PEER"));
		} catch (Exception e) {
			throw new WrongCAConfigurationFileSyntaxException();
		}
	}

}