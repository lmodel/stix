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
  Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixThreatActor extends StixDomainObject {

  private List<String> threatActorTypes;
  private String name;
  private String description;
  private List<String> aliases;
  private List<String> roles;
  private List<String> goals;
  private ZonedDateTime firstSeen;
  private ZonedDateTime lastSeen;
  private String sophistication;
  private String resourceLevel;
  private String primaryMotivation;
  private List<String> secondaryMotivations;
  private List<String> personalMotivations;


}