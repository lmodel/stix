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
  The Process Object represents common properties of an instance of a computer program as executed on an operating system.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixProcess extends StixCyberObservableObject {

  private Boolean isHidden;
  private Integer pid;
  private ZonedDateTime createdTime;
  private String cwd;
  private String commandLine;
  private StixDictionary environmentVariables;
  private List<StixNetworkTraffic> openedConnectionRefs;
  private StixUserAccount creatorUserRef;
  private StixFile imageRef;
  private StixProcess parentRef;
  private List<StixProcess> childRefs;


}