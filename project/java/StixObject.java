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
  Any STIX object: the base of the domain, relationship and cyber-observable objects and of the meta objects.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public abstract class StixObject  {

  private String id;
  private String type;
  private String specVersion;
  private List<StixMarkingDefinition> objectMarkingRefs;
  private List<StixGranularMarking> granularMarkings;
  private StixExtensions extensions;


}