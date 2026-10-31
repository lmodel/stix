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
  The Email Message Object represents an instance of an email message.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixEmailMessage extends StixCyberObservableObject {

  private ZonedDateTime emailDate;
  private String contentType;
  private StixEmailAddress fromRef;
  private StixEmailAddress senderRef;
  private List<StixEmailAddress> toRefs;
  private List<StixEmailAddress> ccRefs;
  private List<StixEmailAddress> bccRefs;
  private String messageId;
  private String subject;
  private List<String> receivedLines;
  private StixDictionary additionalHeaderFields;
  private StixArtifact rawEmailRef;
  private boolean isMultipart;
  private String body;
  private List<StixMimePart> bodyMultipart;


}