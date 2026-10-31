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
  Attack Patterns are a type of TTP that describe ways that adversaries attempt to compromise targets.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixAttackPattern extends StixDomainObject {

  private List<String> aliases;
  private String name;
  private String description;
  private List<StixKillChainPhase> killChainPhases;


}