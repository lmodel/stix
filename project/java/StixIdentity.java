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
  An individual, organization or group, such as ACME, Inc., or a class of them.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixIdentity extends StixDomainObject {

  private List<String> roles;
  private String name;
  private String description;
  private String identityClass;
  private List<String> sectors;
  private String contactInformation;


}