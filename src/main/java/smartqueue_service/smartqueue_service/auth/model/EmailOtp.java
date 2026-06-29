package smartqueue_service.smartqueue_service.auth.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;


@Entity
@Table(name = "email_otp",indexes = { @Index(name = "idx_users_email", columnList = "email", unique = true)})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
    @EntityListeners(AuditingEntityListener.class)
    public class EmailOtp {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(nullable = false,unique = true)
        private String email;

        @Column(name = "otp")
        private String otpHash;

        private Instant expiresAt;

        private boolean used = false;
    }

