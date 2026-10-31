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
  A dictionary of hashes. Each key names a hash algorithm, from the hash-algorithm-ov vocabulary (StixHashAlgorithm) or a custom one, and each value is the hash as a string.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixHashes  {



}