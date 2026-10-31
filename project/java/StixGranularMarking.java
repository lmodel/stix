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
  The granular-marking type defines how the list of marking-definition objects referenced by the marking_refs property to apply to a set of content identified by the list of selectors in the selectors property.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixGranularMarking  {

  private StixMarkingDefinition markingRef;
  private List<String> selectors;
  private String lang;


}