package smartqueue_service.smartqueue_service.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import smartqueue_service.smartqueue_service.auth.model.EmailOtp;

import java.util.Optional;

public interface EmailOtpRepository extends JpaRepository<EmailOtp, Long> {
    Optional<EmailOtp> findTopByEmailAndUsedFalseOrderByIdDesc(String email);
    void deleteOtpByEmail(String email);
}