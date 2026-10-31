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
  The Windows Process extension specifies a default extension for capturing properties specific to Windows processes.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixWindowsProcessExtension  {

  private Boolean aslrEnabled;
  private Boolean depEnabled;
  private String priority;
  private String ownerSid;
  private String windowTitle;
  private StixDictionary startupInfo;
  private String integrityLevel;


}