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
  An NTFS alternate data stream of a file.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixAlternateDataStream  {

  private String name;
  private StixHashes hashes;
  private Integer size;


}