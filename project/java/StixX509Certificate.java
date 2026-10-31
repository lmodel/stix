package example;

/* metamodel_version: 1.12.0 */
/* version: 2.1 */
import java.net.URI;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.util.List;
import lombok.*;

/**
  The X509 Certificate Object represents the properties of an X.509 certificate.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixX509Certificate extends StixCyberObservableObject {

  private Boolean isSelfSigned;
  private StixHashes hashes;
  private String version;
  private String serialNumber;
  private String signatureAlgorithm;
  private String issuer;
  private ZonedDateTime validityNotBefore;
  private ZonedDateTime validityNotAfter;
  private String subject;
  private String subjectPublicKeyAlgorithm;
  private String subjectPublicKeyModulus;
  private Integer subjectPublicKeyExponent;
  private StixX509V3Extensions x509V3Extensions;


}