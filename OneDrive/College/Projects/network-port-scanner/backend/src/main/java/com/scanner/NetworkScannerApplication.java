package com.scanner;

import com.scanner.model.User;
import com.scanner.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class NetworkScannerApplication {

    public static void main(String[] args) {
        SpringApplication.run(NetworkScannerApplication.class, args);
    }

    @Bean
    public CommandLineRunner initData(UserRepository userRepository) {
        return args -> {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            if (userRepository.findByUsername("admin").isEmpty()) {
                User admin = new User("admin", encoder.encode("admin123"), "ADMIN");
                userRepository.save(admin);
                System.out.println("Default administrator account created: admin / admin123");
            }
            if (userRepository.findByUsername("analyst").isEmpty()) {
                User analyst = new User("analyst", encoder.encode("analyst123"), "ANALYST");
                userRepository.save(analyst);
                System.out.println("Default analyst account created: analyst / analyst123");
            }
            if (userRepository.findByUsername("viewer").isEmpty()) {
                User viewer = new User("viewer", encoder.encode("viewer123"), "VIEWER");
                userRepository.save(viewer);
                System.out.println("Default viewer account created: viewer / viewer123");
            }
        };
    }
}
