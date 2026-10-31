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
  The Domain Name represents the properties of a network domain name.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixDomainName extends StixCyberObservableObject {

  private String value;
  private List<StixCyberObservableObject> resolvesToRefs;


}