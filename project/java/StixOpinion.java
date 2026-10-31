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
  An Opinion is an assessment of the correctness of the information in a STIX Object produced by a different entity and captures the level of agreement or disagreement using a fixed scale.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixOpinion extends StixDomainObject {

  private String explanation;
  private List<String> authors;
  private List<StixObject> objectRefs;
  private String opinion;


}