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
  A STIX Domain Object (SDO): a higher-level concept of cyber threat intelligence, such as an attack pattern, a malware family or a threat actor.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public abstract class StixDomainObject extends StixCommonObject {



}