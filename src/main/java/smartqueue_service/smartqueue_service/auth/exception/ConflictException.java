package smartqueue_service.smartqueue_service.auth.exception;

public class ConflictException extends RuntimeException {
    public ConflictException(String message) {
        super(message);
    }
}