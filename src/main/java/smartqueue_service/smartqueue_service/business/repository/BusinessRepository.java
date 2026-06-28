package smartqueue_service.smartqueue_service.business.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import smartqueue_service.smartqueue_service.business.model.Business;

public interface BusinessRepository extends JpaRepository<Business, Long> {

}