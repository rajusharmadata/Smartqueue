package smartqueue_service.smartqueue_service.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import smartqueue_service.smartqueue_service.auth.dto.*;
import smartqueue_service.smartqueue_service.auth.exception.AuthException;
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
import java.util.Optional;

import static smartqueue_service.smartqueue_service.auth.model.User.*;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final EmailOtpService emailOtpService;

    private static final String GENERIC_OTP_SENT_MSG = "If an account exists for this email, a reset code has been sent.";
    private static final String OTP_RESENT_MSG = "OTP resent to ";
    private static final String OTP_SENT_MSG = "OTP sent to ";

    // ── Register ──────────────────────────────────────────────────────────────
    @Transactional
    public String register(RegisterRequest request) {
        String email = normalizeEmail(request.email());

        Optional<User> existingOpt = userRepository.findByEmail(email);

        if (existingOpt.isPresent()) {
            User existing = existingOpt.get();
            if (!existing.isEmailVerified()) {
                emailOtpService.sendOtp(email);
                return OTP_RESENT_MSG + email;
            }
            throw new ConflictException("Email already registered and verified");
        }

        // Phone uniqueness check (only if provided)
        if (request.phone() != null && !request.phone().trim().isEmpty() &&
                userRepository.existsByPhone(request.phone().trim())) {
            throw new ConflictException("Phone number already registered");
        }

        User user = builder()
                .name(request.name().trim())
                .email(email)
                .phone(request.phone() != null ? request.phone().trim() : null)
                .passwordHash(passwordEncoder.encode(request.password()))
                .role(Role.CUSTOMER)
                .emailVerified(false)
                .isActive(true)
                .build();

        userRepository.save(user);
        emailOtpService.sendOtp(email);

        log.info("New user registered (pending verification): {}", email);
        return OTP_SENT_MSG + email;
    }

    // ── Resend OTP ────────────────────────────────────────────────────────────
    @Transactional(readOnly = true)
    public String resendOtp(ResendOtpRequest request) {
        String email = normalizeEmail(request.email());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("No account found with this email"));

        if (user.isEmailVerified()) {
            throw new AuthException("Email is already verified. Please log in.");
        }

        emailOtpService.sendOtp(email);
        log.info("OTP resent for verification: {}", email);
        return OTP_RESENT_MSG + email;
    }

    // ── Verify Email ──────────────────────────────────────────────────────────
    @Transactional
    public AuthResponse verifyEmail(String email, String otp) {
        String normalizedEmail = normalizeEmail(email);

        if (!emailOtpService.verifyOtp(normalizedEmail, otp)) {
            throw new AuthException("Invalid or expired OTP");
        }

        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new AuthException("User not found"));

        user.setEmailVerified(true);
        userRepository.save(user);

        log.info("Email verified successfully: {}", normalizedEmail);
        return buildAuthResponse(user);
    }

    // ── Login ─────────────────────────────────────────────────────────────────
    @Transactional(readOnly = true)
    public AuthResponse login(LoginRequest request) {
        String email = normalizeEmail(request.email());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("Invalid email or password"));

        // Constant-time password comparison (BCrypt is slow by design - security first)
        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new AuthException("Invalid email or password");
        }

        if (!user.isEmailVerified()) {
            throw new AuthException("Email not verified. Please verify your email first.");
        }

        if (!user.isActive()) {
            throw new AuthException("Account is deactivated. Please contact support.");
        }

        log.info("User logged in successfully: {}", email);
        return buildAuthResponseInNewTransaction(user);
    }

    // ── Forgot Password ───────────────────────────────────────────────────────
    @Transactional(readOnly = true)
    public String forgotPassword(ForgotPasswordRequest request) {
        String email = normalizeEmail(request.email());

        // Always return generic message (prevents user enumeration)
        userRepository.findByEmail(email).ifPresent(user -> {
            emailOtpService.sendOtp(email);
            log.info("Password reset OTP sent to: {}", email);
        });

        return GENERIC_OTP_SENT_MSG;
    }

    // ── Reset Password ────────────────────────────────────────────────────────
    @Transactional
    public String resetPassword(ResetPasswordRequest request) {
        String email = normalizeEmail(request.email());

        if (!emailOtpService.verifyOtp(email, request.otp())) {
            throw new AuthException("Invalid or expired OTP");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("User not found"));

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);

        // Security: Invalidate all sessions
        refreshTokenRepository.revokeAllByUserId(user.getId());

        log.info("Password reset successful for: {}", email);
        return "Password reset successful. Please log in with your new password.";
    }

    // ── Refresh Token ─────────────────────────────────────────────────────────
    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        String tokenHash = hashToken(request.refreshToken());

        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (stored.isRevoked() || stored.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("Refresh token is invalid or expired");
        }

        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        return buildAuthResponse(stored.getUser());
    }

    // ── Logout ────────────────────────────────────────────────────────────────
    @Transactional
    public void logout(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            return;
        }

        String tokenHash = hashToken(rawRefreshToken);
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
            log.info("Refresh token revoked for user: {}", token.getUser().getEmail());
        });
    }

    // ── Private Helpers ───────────────────────────────────────────────────────
    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private AuthResponse buildAuthResponse(User user) {
        String accessToken = jwtTokenProvider.generateAccessToken(
                user.getId(), user.getRole(), user.getEmail());

        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getId());

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

    @Transactional
    public AuthResponse buildAuthResponseInNewTransaction(User user) {
        return buildAuthResponse(user);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
}