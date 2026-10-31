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
  The Software Object represents high-level properties associated with software, including software products.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixSoftware extends StixCyberObservableObject {

  private String name;
  private String cpe;
  private String swid;
  private List<String> languages;
  private String vendor;
  private String version;


}