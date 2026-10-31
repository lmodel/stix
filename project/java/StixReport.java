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
  Reports are collections of threat intelligence focused on one or more topics, such as a description of a threat actor, malware, or attack technique, including context and related details.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixReport extends StixDomainObject {

  private List<String> reportTypes;
  private String name;
  private String description;
  private ZonedDateTime published;
  private List<StixObject> objectRefs;


}