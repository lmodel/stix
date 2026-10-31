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
  The Incident object in STIX 2.1 is a stub, to be expanded in future STIX 2 releases.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixIncident extends StixDomainObject {

  private String name;
  private String description;


}