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
  The belief that something in cyber threat intelligence, such as an indicator, malware or a threat actor, was seen.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixSighting extends StixRelationshipObject {

  private String description;
  private ZonedDateTime firstSeen;
  private ZonedDateTime lastSeen;
  private Integer count;
  private StixDomainObject sightingOfRef;
  private List<StixObservedData> observedDataRefs;
  private List<StixDomainObject> whereSightedRefs;
  private Boolean summary;


}