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
  The File Object represents the properties of a file.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixFile extends StixCyberObservableObject {

  private StixHashes hashes;
  private Integer size;
  private String name;
  private String nameEnc;
  private String magicNumberHex;
  private String mimeType;
  private ZonedDateTime ctime;
  private ZonedDateTime mtime;
  private ZonedDateTime atime;
  private StixDirectory parentDirectoryRef;
  private List<StixCyberObservableObject> containsRefs;
  private StixArtifact contentRef;


}