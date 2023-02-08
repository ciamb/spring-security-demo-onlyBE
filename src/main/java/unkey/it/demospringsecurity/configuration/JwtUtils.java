package unkey.it.demospringsecurity.configuration;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Component
public class JwtUtils {

    private String jwtSigningKey = "secret"; // la signingKey deve essere ovviamente più complessa

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean hasClaim(String token, String claimName) {
        final Claims claims = extractAllClaims(token);
        return claims.get(claimName) != null;
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) { return extractExpiration(token).before(new Date()); }

    /*
    * Ci sono due generateToken, uno che prende in ingresso solo lo userDetails, mentre l'altro che prende in
    * ingresso anche i claims, che non sono altro che delle extra informazioni che voglio dare al mio token
    * -> possibile utilizzo dei claims per passarmi le cose in arrivo da azure directory??
    * entrambi i metodi poi ritornano la creazione di un token tramite il metodo subito dopo.
     */
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(userDetails, claims);
    }

    public String generateToken(UserDetails userDetails, Map<String, Object> claims) {
        return createToken(userDetails, claims);
    }

    /*
    * createToken riceve in ingresso userDetails e claims dai metodi generate.
    * Ricordiamo che UserDetails è una classe di spring, qua io potrei passarmi la mia entità che utilizzo
    * per loggare nell'applicativo. Per renderci la vita molto, molto, molto più facile se usiamo una classe personalizzata
    * per la login è bene che questa implementi l'interfaccia di UserDetails di Spring.
     */
    private String createToken(UserDetails userDetails, Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token)); // compara il token in arrivo e vede se è valido
    }
}
