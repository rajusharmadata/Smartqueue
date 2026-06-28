package smartqueue_service.smartqueue_service.business.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import smartqueue_service.smartqueue_service.business.model.Business;
import smartqueue_service.smartqueue_service.business.repository.BusinessRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class businessService {

    private final BusinessRepository repository;

    public List<Business> getBusinesses() {
        return repository.findAll();
    }

    public Business createBusiness(
            String name,
            String type,
            String address) {

        Business business = Business.builder()
                .businessName(name)
                .businessType(type)
                .address(address)
                .active(true)
                .build();

        return repository.save(business);
    }
}