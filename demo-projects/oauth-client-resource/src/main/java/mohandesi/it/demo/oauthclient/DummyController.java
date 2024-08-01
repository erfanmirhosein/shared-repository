package mohandesi.it.demo.oauthclient;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class DummyController {

    @GetMapping("/admin/hello")
    public String helloAdmin() {
        return new String("hello to the admin");
    }

    @GetMapping("/user/hello")
    public String helloUser() {
        return new String("hello to the user");
    }

}
