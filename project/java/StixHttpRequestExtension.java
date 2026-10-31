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
  The HTTP request extension specifies a default extension for capturing network traffic properties specific to HTTP requests.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixHttpRequestExtension  {

  private String requestMethod;
  private String requestValue;
  private String requestVersion;
  private StixDictionary requestHeader;
  private Integer messageBodyLength;
  private StixArtifact messageBodyDataRef;


}