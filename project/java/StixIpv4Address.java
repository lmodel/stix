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
  The IPv4 Address Object represents one or more IPv4 addresses expressed using CIDR notation.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixIpv4Address extends StixCyberObservableObject {

  private String value;
  private List<StixMacAddress> resolvesToRefs;
  private List<StixAutonomousSystem> belongsToRefs;


}