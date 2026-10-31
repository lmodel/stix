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
  The standard X.509 v3 extensions of a certificate.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixX509V3Extensions  {

  private String basicConstraints;
  private String nameConstraints;
  private String policyConstraints;
  private String keyUsage;
  private String extendedKeyUsage;
  private String subjectKeyIdentifier;
  private String authorityKeyIdentifier;
  private String subjectAlternativeName;
  private String issuerAlternativeName;
  private String subjectDirectoryAttributes;
  private String crlDistributionPoints;
  private String inhibitAnyPolicy;
  private ZonedDateTime privateKeyUsagePeriodNotBefore;
  private ZonedDateTime privateKeyUsagePeriodNotAfter;
  private String certificatePolicies;
  private String policyMappings;


}