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
  The UNIX account extension of a user account: its group, its other groups, its home directory and its shell.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixUnixAccountExtension  {

  private Float gid;
  private List<String> groups;
  private String homeDir;
  private String shell;


}