package smartqueue_service.smartqueue_service.auth.service;

import jakarta.security.auth.message.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import smartqueue_service.smartqueue_service.auth.dto.Role;
import smartqueue_service.smartqueue_service.auth.dto.AuthResponse;
import smartqueue_service.smartqueue_service.auth.dto.LoginRequest;
import smartqueue_service.smartqueue_service.auth.dto.RefreshTokenRequest;
import smartqueue_service.smartqueue_service.auth.dto.RegisterRequest;
import smartqueue_service.smartqueue_service.auth.exception.ConflictException;
import smartqueue_service.smartqueue_service.auth.model.RefreshToken;
import smartqueue_service.smartqueue_service.auth.model.User;
import smartqueue_service.smartqueue_service.auth.repository.RefreshTokenRepository;
import smartqueue_service.smartqueue_service.auth.repository.UserRepository;
import smartqueue_service.smartqueue_service.auth.security.JwtTokenProvider;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    private final EmailOtpService emailOtpService;  // add this field

    @Transactional
    public String register(RegisterRequest request) {          // return type String now
        if (userRepository.existsByEmail(request.email())) {
            User existing = userRepository.findByEmail(request.email().toLowerCase()).get();
            if (!existing.isEmailVerified()) {
                emailOtpService.sendOtp(request.email());
                return "OTP resent to " + request.email();
            }
            throw new ConflictException("Email already registered");
        }
        if (request.phone() != null && userRepository.existsByPhone(request.phone())) {
            throw new ConflictException("Phone number already registered");
        }

        User user = User.builder()
                .name(request.name())
                .email(request.email().toLowerCase())
                .phone(request.phone())
                .passwordHash(passwordEncoder.encode(request.password()))
                .role(Role.CUSTOMER)
                .emailVerified(false)                          // unverified
                .build();

        userRepository.save(user);
        emailOtpService.sendOtp(request.email());              // send OTP
        log.info("User registered (pending verification): {}", user.getEmail());
        return "OTP sent to " + request.email() ;
    }

    @Transactional
    public AuthResponse verifyEmail(String email, String otp) throws AuthException {
        boolean valid = emailOtpService.verifyOtp(email, otp);
        if (!valid) throw new AuthException("Invalid or expired OTP");

        User user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new AuthException("User not found"));

        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified: {}", email);
        return buildAuthResponse(user);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) throws AuthException {
        User user = userRepository.findByEmail(request.email().toLowerCase())
                .orElseThrow(() -> new AuthException("Invalid email or password"));

        if (!user.isEmailVerified()) {
            throw new AuthException("Email not verified. Please verify your email first.");
        }

        if (!user.isActive()) {
            throw new AuthException("Account is deactivated. Please contact support.");
        }


        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new AuthException("Invalid email or password");
        }

        log.info("User logged in: {}", user.getEmail());
        return buildAuthResponse(user);
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) throws AuthException {
        String tokenHash = hashToken(request.refreshToken());

        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (stored.isRevoked()) {
            throw new AuthException("Refresh token has been revoked");
        }

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("Refresh token has expired");
        }

        // Rotate: revoke old, issue new
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        return buildAuthResponse(stored.getUser());
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        String tokenHash = hashToken(rawRefreshToken);
        refreshTokenRepository.findByTokenHash(tokenHash)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    refreshTokenRepository.save(token);
                });
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private AuthResponse buildAuthResponse(User user) {
        String accessToken  = jwtTokenProvider.generateAccessToken(user.getId(), user.getRole(), user.getEmail());
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

        // Persist hashed refresh token
        RefreshToken tokenEntity = RefreshToken.builder()
                .tokenHash(hashToken(refreshToken))
                .user(user)
                .expiresAt(Instant.now().plusMillis(jwtTokenProvider.getRefreshExpiryMs()))
                .build();

        refreshTokenRepository.save(tokenEntity);

        return new AuthResponse(
                accessToken,
                refreshToken,
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRole()
        );
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}