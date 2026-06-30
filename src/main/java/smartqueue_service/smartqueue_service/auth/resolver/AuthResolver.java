package smartqueue_service.smartqueue_service.auth.resolver;

import jakarta.security.auth.message.AuthException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;
import smartqueue_service.smartqueue_service.auth.annotation.RequireAuth;
import smartqueue_service.smartqueue_service.auth.dto.*;
import smartqueue_service.smartqueue_service.auth.service.AuthService;

@Controller
@RequiredArgsConstructor
public class AuthResolver {

    private final AuthService authService;

    @MutationMapping
    public String register(@Argument @Valid RegisterRequest input) {
        return authService.register(input);
    }

    @MutationMapping
    public String resendOtp(@Argument @Valid ResendOtpRequest input) throws AuthException {
        return authService.resendOtp(input);
    }

    @MutationMapping
    public AuthResponse verifyEmail(@Argument @Valid VerifyEmailRequest input) throws AuthException {
        return authService.verifyEmail(input.email(), input.otp());
    }

    @MutationMapping
    public AuthResponse login(@Argument @Valid LoginRequest input) throws AuthException {
        return authService.login(input);
    }

    @MutationMapping
    public String forgotPassword(@Argument @Valid ForgotPasswordRequest input) {
        return authService.forgotPassword(input);
    }

    @MutationMapping
    public String resetPassword(@Argument @Valid ResetPasswordRequest input) throws AuthException {
        return authService.resetPassword(input);
    }

    @MutationMapping
    public AuthResponse refreshToken(@Argument @Valid RefreshTokenRequest input) throws AuthException {
        return authService.refresh(input);
    }

    @MutationMapping
    @RequireAuth
    public Boolean logout(@Argument String refreshToken) {
        authService.logout(refreshToken);
        return true;
    }

    @QueryMapping
    @RequireAuth
    public String me() {
        return "Authenticated";
    }
}