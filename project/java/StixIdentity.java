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
  Identities can represent actual individuals, organizations, or groups (e.g., ACME, Inc.) as well as classes of individuals, organizations, or groups.
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