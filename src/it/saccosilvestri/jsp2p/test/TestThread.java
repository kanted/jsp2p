package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.exceptions.BadNonceException;
import it.saccosilvestri.jsp2p.securecommunication.Peer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TestThread extends Thread {

	Peer peer;
	Socket mySocket;

	public TestThread(String myPath, String caPath, int port, boolean passive,
			KeyPair kp) throws IOException, InvalidKeyException,
			CertificateException, NoSuchAlgorithmException,
			NoSuchProviderException, SignatureException,
			NoSuchPaddingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeySpecException, BadNonceException {
		if (passive) {
			ServerSocket server = new ServerSocket(8080);
			mySocket = server.accept();
		} else
			mySocket = new Socket("localhost", port);
		FileInputStream f = new FileInputStream(caPath);
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		X509Certificate caCert = (X509Certificate) fact.generateCertificate(f);
		f = new FileInputStream(myPath);
		X509Certificate peerCert = (X509Certificate) fact
				.generateCertificate(f);
		peer = new Peer(passive, mySocket, kp, peerCert, caCert);
		this.start();
	}

	public void run() {
		try {
			System.out.println("Starting thread");
			byte[] b = null;
			String command = null;
			while (command != "quit") {

				System.in.read(b);

				command = new String(b, "US-ASCII");

				if (command == "send") {
					System.in.read(b);
					peer.send(b);
				}
				
				if (command == "receive") {
					peer.receive(b);
					String app = new String(b, "US-ASCII");
					System.out.println(app);
				}
			}

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getMessage());
		}
	}

}
