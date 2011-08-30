package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.exceptions.UnreachableCAConfigurationFileException;
import it.saccosilvestri.jsp2p.exceptions.WrongCAConfigurationFileSyntaxException;
import it.saccosilvestri.jsp2p.securecommunication.SecureCommunication;
import it.saccosilvestri.jsp2p.utility.CertificateUtility;
import it.saccosilvestri.jsp2p.utility.ConfigurationFileUtility;
import it.saccosilvestri.jsp2p.utility.FileUtility;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Properties;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class Peer {

	/**
	 * Recupera il certificato della CA ed il certificato e le chiavi (pubblica e privata) del peer.
	 * Infine, avvia i due thread necessari all'esecuzione del protocollo.
	 */
	public static void main(String[] args) {

		try {
			if (args.length < 2) {
				System.out
						.println("Sintassi: java Peer [numero identificativo del peer] [porta]");
				return;
			}
			// Recupero il numero del peer.
			int i = Integer.parseInt(args[0]);
			// Recupero la porta.
			int port = Integer.parseInt(args[1]);
			if (port < 1024 || port > 65535) {
				System.out
						.println("Attenzione. Inserire un numero di porta valido.");
				return;
			}
			System.out.println("Starting peer " + i);
			System.out.println("Recuperando il certificato per il peer " + i);
			X509Certificate caCert = CertificateUtility
					.readCertificate("ca_certificate.crt");
			X509Certificate peerCert = CertificateUtility
					.readCertificate("certificate_for_peer_" + i + ".crt"); 
			System.out.println("Recuperando le chiavi per il peer " + i);
			KeyPair kp = FileUtility.readKeysFromFiles("public" + i + ".key",
					"private" + i + ".key"); 
			
			// Un peer e' sia alice che bob contemporaneamente.
			CommunicationContainer cc = new CommunicationContainer();
			AliceThread a = new AliceThread(new Integer(i).toString(), peerCert, caCert, port, kp, cc);
			BobThread b = new BobThread(peerCert, caCert, port, kp, cc);

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - "
					+ e.getMessage());
		}
	}

}
