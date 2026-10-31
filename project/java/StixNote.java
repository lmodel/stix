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
  A Note is a comment or note containing informative text to help explain the context of one or more STIX Objects (SDOs or SROs) or to provide additional analysis that is not contained in the original object.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixNote extends StixDomainObject {

  private String abstract_;
  private String content;
  private List<String> authors;
  private List<StixObject> objectRefs;


}