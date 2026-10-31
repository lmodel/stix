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
  The NTFS file extension specifies a default extension for capturing properties specific to the storage of the file on the NTFS file system.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixNtfsExtension  {

  private String sid;
  private List<StixAlternateDataStream> alternateDataStreams;


}