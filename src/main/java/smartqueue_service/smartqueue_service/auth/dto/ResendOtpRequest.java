package smartqueue_service.smartqueue_service.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record ResendOtpRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email
) {}