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
  An Intrusion Set is a grouped set of adversary behavior and resources with common properties that is believed to be orchestrated by a single organization.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixIntrusionSet extends StixDomainObject {

  private String name;
  private String description;
  private List<String> aliases;
  private ZonedDateTime firstSeen;
  private ZonedDateTime lastSeen;
  private List<String> goals;
  private String resourceLevel;
  private String primaryMotivation;
  private List<String> secondaryMotivations;


}