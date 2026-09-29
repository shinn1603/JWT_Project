package vn.yain.configs;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import vn.yain.entity.User;
import vn.yain.repository.UserRepository;

@Configuration
public class DataInitializer {

    @Bean
    CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByEmail("tho8189@gmail.com").isEmpty()) {
                User user = new User();
                user.setFullName("Nguyễn Phước Thọ");
                user.setEmail("tho8189@gmail.com");
                user.setPassword(passwordEncoder.encode("123456"));
                user.setImages("default.jpg");
                userRepository.save(user);
            }
        };
    }
}
