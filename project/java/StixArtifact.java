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
  The Artifact Object permits capturing an array of bytes (8-bits), as a base64-encoded string string, or linking to a file-like payload.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixArtifact extends StixCyberObservableObject {

  private String mimeType;
  private String payloadBin;
  private URI url;
  private StixHashes hashes;
  private String encryptionAlgorithm;
  private String decryptionKey;


}