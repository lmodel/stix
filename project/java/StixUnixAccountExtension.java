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
  The User Account Object defines the following extensions. In addition to these, producers MAY create their own.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixUnixAccountExtension  {

  private Float gid;
  private List<String> groups;
  private String homeDir;
  private String shell;


}