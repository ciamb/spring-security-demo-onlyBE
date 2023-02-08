package unkey.it.demospringsecurity.configuration;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import unkey.it.demospringsecurity.repository.UserRepository;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAthFilter jwtAthFilter;

    private final UserRepository userRepository;

    /*
    * La prima cosa che fa spring security all'avvio dell'applicativo è quello di cercare un oggetto
    * o il bean di SecurityFilterChain!
    * Solamente con la security filter chain posso fare un autenticazione di spring base,
    * però questa è soggetta a vulnerabilità e quindi abbiamo bisogno di aggiungere
    * un altro livello di sicurezza. Qui entrano in gioco i JwtToken!
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/**/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Con la policy gestiamo la sessione per evitare che rimanga salvata. IMPORTANTISSIMO
                .and()
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAthFilter, UsernamePasswordAuthenticationFilter.class)

                ;

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); // qua andrebbe inserito il tipo di crittografia per la nostra password!
    }


    /*
    * Invece di fare il @Bean di questa classe va semplicemente creata una classe UserDetailsServiceImpl che
    * implementa l'interfaccia di security e che fa l' @Override del metodo loadByUsername. (Molto facile)
    * Poi andare a utilizzare quella all'interno del JwtAthFilter
     */
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userRepository.findUserByEmail(email);
            }
        };
    }

}
