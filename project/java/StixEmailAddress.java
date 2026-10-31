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
  The Email Address Object represents a single email address.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixEmailAddress extends StixCyberObservableObject {

  private String value;
  private String displayName;
  private StixUserAccount belongsToRef;


}