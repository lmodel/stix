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
  A marking definition: a statement, a Traffic Light Protocol (TLP) level or another marking that applies to the objects that reference it.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixMarkingDefinition extends StixObject {

  private StixIdentity createdByRef;
  private ZonedDateTime created;
  private List<StixExternalReference> externalReferences;
  private String name;
  private String definitionType;
  private String definition;


}