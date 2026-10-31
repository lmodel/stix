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
  Infrastructure objects describe systems, software services, and associated physical or virtual resources.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixInfrastructure extends StixDomainObject {

  private String name;
  private String description;
  private List<String> infrastructureTypes;
  private List<String> aliases;
  private List<StixKillChainPhase> killChainPhases;
  private ZonedDateTime firstSeen;
  private ZonedDateTime lastSeen;


}