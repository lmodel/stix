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
  The base of the objects that carry STIX's common properties: the domain and relationship objects, language content and extension definitions.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public abstract class StixCommonObject extends StixObject {

  private StixIdentity createdByRef;
  private ZonedDateTime created;
  private ZonedDateTime modified;
  private Boolean revoked;
  private List<String> labels;
  private Integer confidence;
  private String lang;
  private List<StixExternalReference> externalReferences;


}