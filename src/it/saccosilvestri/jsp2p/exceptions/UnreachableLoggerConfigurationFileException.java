package it.saccosilvestri.jsp2p.exceptions;

public class UnreachableLoggerConfigurationFileException extends Exception {

	public String getMessage() {
		return "Logger configuration File not found or not readable";

	}
}
