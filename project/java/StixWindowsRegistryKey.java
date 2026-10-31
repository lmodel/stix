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
  The Registry Key Object represents the properties of a Windows registry key.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixWindowsRegistryKey extends StixCyberObservableObject {

  private String key;
  private List<StixWindowsRegistryValue> values;
  private ZonedDateTime modifiedTime;
  private StixUserAccount creatorUserRef;
  private Integer numberOfSubkeys;


}