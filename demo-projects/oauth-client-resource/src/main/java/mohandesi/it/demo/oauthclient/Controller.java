package mohandesi.it.demo.oauthclient;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class Controller {

    @GetMapping("/hello")
    public String getMethodName() {
        return new String("hello");
    }

}
