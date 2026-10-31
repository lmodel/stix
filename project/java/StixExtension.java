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
  An extension of an object that an extension definition defines. Besides its extension type it carries the properties that its definition's schema states.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixExtension  {

  private String extensionType;


}