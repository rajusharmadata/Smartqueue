package smartqueue_service.smartqueue_service.auth.dto;


import java.util.UUID;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        UUID userId,
        String name,
        String email,
        Role role
) {}