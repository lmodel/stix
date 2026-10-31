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
  The AS object represents the properties of an Autonomous Systems (AS).
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixAutonomousSystem extends StixCyberObservableObject {

  private int number;
  private String name;
  private String rir;


}