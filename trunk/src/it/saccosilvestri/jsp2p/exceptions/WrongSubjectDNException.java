package it.saccosilvestri.jsp2p.exceptions;

import java.security.cert.CertificateException;

public class WrongSubjectDNException extends CertificateException {

	public String getMessage() {
		return "Wrong Subject DN.";

	}
}
