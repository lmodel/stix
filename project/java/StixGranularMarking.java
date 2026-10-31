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
  A marking of parts of an object: the properties its selectors name, marked either by a marking definition or with a language.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixGranularMarking  {

  private StixMarkingDefinition markingRef;
  private List<String> selectors;
  private String lang;


}