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
  The definition of a Traffic Light Protocol (TLP) marking: its level.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixTlpMarking  {

  private String tlp;


}