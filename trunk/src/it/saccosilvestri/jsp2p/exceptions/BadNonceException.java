package it.saccosilvestri.jsp2p.exceptions;

public class BadNonceException extends Exception {

	public String getMessage() {
		return "Received nonce is different from the one sent.";

	}

}
