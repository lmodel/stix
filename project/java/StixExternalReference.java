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
  External references are used to describe pointers to information represented outside of STIX.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixExternalReference  {

  private String sourceName;
  private String description;
  private URI url;
  private StixHashes hashes;
  private String externalId;


}