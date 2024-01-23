package de.zeus.keycloakdemo.exception;

// Custom exception for payload parsing
public class PayloadParseException extends RuntimeException {
    public PayloadParseException(String message, Throwable cause) {
        super(message, cause);
    }
}