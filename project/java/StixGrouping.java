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
  A Grouping object explicitly asserts that the referenced STIX Objects have a shared content.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixGrouping extends StixDomainObject {

  private String name;
  private String description;
  private String context;
  private List<StixObject> objectRefs;


}