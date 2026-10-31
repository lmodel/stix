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
  One MIME part of a multipart email body.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixMimePart  {

  private String body;
  private StixCyberObservableObject bodyRawRef;
  private String contentType;
  private String contentDisposition;


}