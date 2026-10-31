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
  A STIX Cyber-observable Object (SCO): a fact observed on a network or host, such as a file, an address or a process.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public abstract class StixCyberObservableObject extends StixObject {

  private Boolean defanged;


}