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
  The Windows Service extension specifies a default extension for capturing properties specific to Windows services.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixWindowsServiceExtension  {

  private String serviceName;
  private List<String> descriptions;
  private String displayName;
  private String groupName;
  private String startType;
  private List<StixFile> serviceDllRefs;
  private String serviceType;
  private String serviceStatus;


}