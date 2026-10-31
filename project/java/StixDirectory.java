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
  The Directory Object represents the properties common to a file system directory.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixDirectory extends StixCyberObservableObject {

  private String path;
  private String pathEnc;
  private ZonedDateTime ctime;
  private ZonedDateTime mtime;
  private ZonedDateTime atime;
  private List<StixCyberObservableObject> containsRefs;


}