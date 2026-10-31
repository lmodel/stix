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
  The language-content object represents text content for STIX Objects represented in languages other than that of the original object.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixLanguageContent extends StixCommonObject {

  private StixObject objectRef;
  private ZonedDateTime objectModified;
  private StixLanguageContents contents;


}