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
  A Campaign is a grouping of adversary behavior that describes a set of malicious activities or attacks that occur over a period of time against a specific set of targets.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixCampaign extends StixDomainObject {

  private String name;
  private String description;
  private List<String> aliases;
  private ZonedDateTime firstSeen;
  private ZonedDateTime lastSeen;
  private String objective;


}