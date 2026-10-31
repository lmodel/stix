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
  A bundle: a collection of STIX objects grouped together in one container. A bundle is a container for transport, not a STIX object, so it carries no spec_version.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixBundle  {

  private String id;
  private String type;
  private List<StixObject> objects;


}