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
  The STIX Extension Definition object allows producers of threat intelligence to extend existing STIX objects or to create entirely new STIX objects in a standardized way.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixExtensionDefinition extends StixCommonObject {

  private String name;
  private String description;
  private String schema;
  private String version;
  private List<String> extensionTypes;
  private List<String> extensionProperties;


}