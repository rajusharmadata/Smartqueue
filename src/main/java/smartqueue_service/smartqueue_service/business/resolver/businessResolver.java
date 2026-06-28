package smartqueue_service.smartqueue_service.business.resolver;

import lombok.RequiredArgsConstructor;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.stereotype.Controller;
import smartqueue_service.smartqueue_service.business.model.Business;
import smartqueue_service.smartqueue_service.business.service.businessService;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class businessResolver {

    private final businessService service;

    @QueryMapping
    public List<Business> businesses() {
        return service.getBusinesses();
    }

    @MutationMapping
    public Business createBusiness(
            @Argument String name,
            @Argument String type,
            @Argument String address) {

        return service.createBusiness(
                name,
                type,
                address
        );
    }
}