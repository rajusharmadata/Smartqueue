package smartqueue_service.smartqueue_service.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import smartqueue_service.smartqueue_service.auth.model.EmailOtp;
import smartqueue_service.smartqueue_service.auth.repository.EmailOtpRepository;

import jakarta.mail.internet.MimeMessage;
import java.security.SecureRandom;
import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailOtpService {

    private final EmailOtpRepository emailOtpRepository;
    private final JavaMailSender mailSender;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long OTP_VALIDITY_MINUTES = 5;
    private static final long OTP_VALID_MS = OTP_VALIDITY_MINUTES * 60 * 1000L;
    private static final int OTP_LENGTH = 6;

    /**
     * Send OTP - DB write is synchronous, email is asynchronous.
     */
    public void sendOtp(String email) {
        String normalizedEmail = normalizeEmail(email);
        String otp = generateOtp();

        upsertOtpRecord(normalizedEmail, otp);
        sendOtpEmailAsync(normalizedEmail, otp);

        log.debug("OTP generated and stored for: {}", normalizedEmail);
    }

    public boolean verifyOtp(String email, String otp) {
        if (email == null || otp == null || otp.length() != OTP_LENGTH) {
            return false;
        }

        String normalizedEmail = normalizeEmail(email);

        return emailOtpRepository.findByEmail(normalizedEmail)
                .filter(record -> !record.isUsed())
                .filter(record -> record.getExpiresAt().isAfter(Instant.now()))
                .filter(record -> record.getOtp().equals(otp))
                .map(record -> {
                    record.setUsed(true);
                    emailOtpRepository.save(record);
                    log.debug("OTP verified and marked used for: {}", normalizedEmail);
                    return true;
                })
                .orElse(false);
    }

    // ── Private Helpers ───────────────────────────────────────────────────────

    private void upsertOtpRecord(String email, String otp) {
        EmailOtp record = emailOtpRepository.findByEmail(email)
                .orElseGet(() -> EmailOtp.builder().email(email).build());

        record.setOtp(otp);
        record.setExpiresAt(Instant.now().plusMillis(OTP_VALID_MS));
        record.setUsed(false);

        emailOtpRepository.save(record);
    }

    private String generateOtp() {
        int number = 100_000 + RANDOM.nextInt(900_000);
        return String.valueOf(number);
    }

    @Async("otpExecutor")
    public void sendOtpEmailAsync(String email, String otp) {
        try {
            sendMail(email, otp);
            log.info("OTP email sent successfully to: {}", email);
        } catch (Exception e) {
            // Do not fail the business flow if email sending fails
            log.error("Failed to send OTP email to {}: {}", email, e.getMessage(), e);
        }
    }

    private void sendMail(String email, String otp) throws Exception {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(email);
        helper.setSubject("Your Quptos verification code");
        helper.setText(buildHtmlTemplate(otp), true);

        mailSender.send(message);
    }

    private String buildHtmlTemplate(String otp) {
        String template = """
            <!DOCTYPE html>
            <html>
            <head>
              <meta charset="UTF-8">
              <meta name="viewport" content="width=device-width, initial-scale=1.0">
            </head>
            <body style="margin:0;padding:0;background-color:#F8FAFC;font-family:Arial,sans-serif;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td align="center" style="padding:40px 0;">
                    <table width="480" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">
                      <tr>
                        <td align="center" style="background:#0F2D52;padding:32px 40px;">
                          <h1 style="margin:0;color:#ffffff;font-size:24px;font-weight:700;letter-spacing:0.5px;">Quptos</h1>
                        </td>
                      </tr>
                      <tr>
                        <td style="padding:40px;">
                          <p style="margin:0 0 8px;color:#111827;font-size:20px;font-weight:600;">Verify your email</p>
                          <p style="margin:0 0 32px;color:#6B7280;font-size:14px;line-height:1.6;">
                            Use the code below to complete your registration.<br>
                            This code expires in <strong>5 minutes</strong>.
                          </p>
                          <table width="100%" cellpadding="0" cellspacing="0">
                            <tr>
                              <td align="center">
                                <div style="display:inline-block;background:#EFF6FF;border:2px dashed #1A56DB;border-radius:12px;padding:20px 48px;">
                                  <span style="font-size:36px;font-weight:800;letter-spacing:12px;color:#1A56DB;">%s</span>
                                </div>
                              </td>
                            </tr>
                          </table>
                          <p style="margin:32px 0 0;color:#9CA3AF;font-size:12px;text-align:center;line-height:1.6;">
                            If you didn't request this, you can safely ignore this email.<br>
                            Do not share this code with anyone.
                          </p>
                        </td>
                      </tr>
                      <tr>
                        <td align="center" style="background:#F9FAFB;padding:20px 40px;border-top:1px solid #E5E7EB;">
                          <p style="margin:0;color:#9CA3AF;font-size:12px;">© 2026 Quptos. All rights reserved.</p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </body>
            </html>
            """.formatted(otp);

        return template;
    }

    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }
}