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
  A Course of Action is an action taken either to prevent an attack or to respond to an attack that is in progress.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixCourseOfAction extends StixDomainObject {

  private String name;
  private String description;


}