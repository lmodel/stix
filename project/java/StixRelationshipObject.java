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
  A STIX Relationship Object (SRO): a relationship or a sighting that links other objects.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public abstract class StixRelationshipObject extends StixCommonObject {



}