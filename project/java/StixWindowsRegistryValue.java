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
  A value found under a Windows registry key.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixWindowsRegistryValue  {

  private String name;
  private String data;
  private String dataType;


}