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
  The MAC Address Object represents a single Media Access Control (MAC) address.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixMacAddress extends StixCyberObservableObject {

  private String value;


}