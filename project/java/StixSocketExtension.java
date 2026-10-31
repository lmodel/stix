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
  The Network Socket extension specifies a default extension for capturing network traffic properties associated with network sockets.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixSocketExtension  {

  private String addressFamily;
  private Boolean isBlocking;
  private Boolean isListening;
  private StixSocketOptions options;
  private String socketType;
  private Integer socketDescriptor;
  private Integer socketHandle;


}