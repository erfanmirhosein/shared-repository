package erfan.java.demo.primefaces;

// import javax.faces.webapp.FacesServlet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;

import jakarta.faces.webapp.FacesServlet;

@SpringBootApplication
public class PrimefacesApplication {

	public static void main(String[] args) {
		SpringApplication.run(PrimefacesApplication.class, args);
	}

}
