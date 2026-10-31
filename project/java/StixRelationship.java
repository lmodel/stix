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
  The Relationship object is used to link together two SDOs in order to describe how they are related to each other.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixRelationship extends StixRelationshipObject {

  private String relationshipType;
  private String description;
  private StixObject sourceRef;
  private StixObject targetRef;
  private ZonedDateTime startTime;
  private ZonedDateTime stopTime;


}