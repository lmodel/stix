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
  The Archive File extension specifies a default extension for capturing properties specific to archive files.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixArchiveExtension  {

  private List<StixCyberObservableObject> containsRefs;
  private String comment;


}