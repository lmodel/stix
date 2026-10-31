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
  Indicators contain a pattern that can be used to detect suspicious or malicious cyber activity.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixIndicator extends StixDomainObject {

  private List<String> indicatorTypes;
  private String name;
  private String description;
  private String pattern;
  private String patternType;
  private String patternVersion;
  private ZonedDateTime validFrom;
  private ZonedDateTime validUntil;
  private List<StixKillChainPhase> killChainPhases;


}