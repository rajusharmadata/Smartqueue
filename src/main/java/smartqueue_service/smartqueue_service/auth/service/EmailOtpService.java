package smartqueue_service.smartqueue_service.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import smartqueue_service.smartqueue_service.auth.model.EmailOtp;
import smartqueue_service.smartqueue_service.auth.repository.EmailOtpRepository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailOtpService {

    private final EmailOtpRepository otpRepository;
    private final JavaMailSender mailSender;
    private static final long OTP_EXPIRY_MINUTES = 5;

    @Transactional
    public void sendOtp(String email) {
        String otp = String.format("%06d", new SecureRandom().nextInt(999999));
        otpRepository.deleteOtpByEmail(email.toLowerCase());
        otpRepository.save(EmailOtp.builder()
                .email(email.toLowerCase())
                .otpHash(hashOtp(otp))
                .expiresAt(Instant.now().plusSeconds(OTP_EXPIRY_MINUTES * 60))
                .build());
        sendMail(email, otp);
        log.info("OTP sent to {} {}", email,otp);
    }

    public boolean verifyOtp(String email, String otp) {
        return otpRepository.findTopByEmailAndUsedFalseOrderByIdDesc(email.toLowerCase())
                .filter(e -> e.getExpiresAt().isAfter(Instant.now()))
                .filter(e -> e.getOtpHash().equals(hashOtp(otp)))
                .map(e -> {
                    e.setUsed(true);
                    e.setOtpHash(null);
                    otpRepository.save(e);
                    return true;
                })
                .orElse(false);
    }

    private void sendMail(String to, String otp) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setTo(to);
            helper.setSubject("Verify your email - SmartQueue");
            helper.setText(buildHtmlTemplate(otp), true); // true = isHtml
            mailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException("Failed to send email", e);
        }
    }

    private String hashOtp(String otp) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(
                    digest.digest(otp.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }
    private String buildHtmlTemplate(String otp) {
        return """
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0;padding:0;background-color:#f4f4f4;font-family:Arial,sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td align="center" style="padding:40px 0;">
                <table width="480" cellpadding="0" cellspacing="0"
                       style="background:#ffffff;border-radius:12px;
                              box-shadow:0 2px 8px rgba(0,0,0,0.08);overflow:hidden;">

                  <!-- Header -->
                  <tr>
                    <td align="center"
                        style="background:#4F46E5;padding:32px 40px;">
                      <h1 style="margin:0;color:#ffffff;font-size:24px;
                                 font-weight:700;letter-spacing:0.5px;">
                        SmartQueue
                      </h1>
                    </td>
                  </tr>

                  <!-- Body -->
                  <tr>
                    <td style="padding:40px;">
                      <p style="margin:0 0 8px;color:#111827;font-size:20px;
                                 font-weight:600;">
                        Verify your email
                      </p>
                      <p style="margin:0 0 32px;color:#6B7280;font-size:14px;
                                 line-height:1.6;">
                        Use the code below to complete your registration.
                        This code expires in <strong>5 minutes</strong>.
                      </p>

                      <!-- OTP Box -->
                      <table width="100%" cellpadding="0" cellspacing="0">
                        <tr>
                          <td align="center">
                            <div style="display:inline-block;
                                        background:#F3F4F6;
                                        border:2px dashed #4F46E5;
                                        border-radius:12px;
                                        padding:20px 48px;">
                              <span style="font-size:36px;font-weight:800;
                                           letter-spacing:12px;color:#4F46E5;">
                                %s
                              </span>
                            </div>
                          </td>
                        </tr>
                      </table>

                      <p style="margin:32px 0 0;color:#9CA3AF;font-size:12px;
                                 text-align:center;line-height:1.6;">
                        If you didn't request this, you can safely ignore this email.<br>
                        Do not share this code with anyone.
                      </p>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td align="center"
                        style="background:#F9FAFB;padding:20px 40px;
                               border-top:1px solid #E5E7EB;">
                      <p style="margin:0;color:#9CA3AF;font-size:12px;">
                        © 2025 SmartQueue. All rights reserved.
                      </p>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """.formatted(otp);
    }
}