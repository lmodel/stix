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
  Observed data conveys information that was observed on systems and networks, such as log data or network traffic, using the Cyber Observable specification.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixObservedData extends StixDomainObject {

  private ZonedDateTime firstObserved;
  private ZonedDateTime lastObserved;
  private int numberObserved;
  private StixObservedObjects objects;
  private List<StixObject> objectRefs;


}