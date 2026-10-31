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
  Tools are legitimate software that can be used by threat actors to perform attacks.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixTool extends StixDomainObject {

  private List<String> aliases;
  private List<String> toolTypes;
  private String name;
  private String description;
  private String toolVersion;
  private List<StixKillChainPhase> killChainPhases;


}