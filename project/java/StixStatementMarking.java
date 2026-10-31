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
  The definition of a statement marking: a statement, such as a copyright or terms of use.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixStatementMarking  {

  private String statement;


}