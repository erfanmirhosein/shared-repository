package mohandesi.it.demo.oauth.controller;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DummyController {

    @GetMapping("/")
    public String getIndexPage(OAuth2AccessToken token) {
        return "THIS IS THE INDEX PAGE";
    }

}
