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
  The Network Traffic Object represents arbitrary network traffic that originates from a source and is addressed to a destination.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixNetworkTraffic extends StixCyberObservableObject {

  private ZonedDateTime start;
  private ZonedDateTime end;
  private StixCyberObservableObject srcRef;
  private StixCyberObservableObject dstRef;
  private Integer srcPort;
  private Integer dstPort;
  private List<String> protocols;
  private Integer srcByteCount;
  private Integer dstByteCount;
  private Integer srcPackets;
  private Integer dstPackets;
  private StixDictionary ipfix;
  private StixArtifact srcPayloadRef;
  private StixArtifact dstPayloadRef;
  private List<StixNetworkTraffic> encapsulatesRefs;
  private StixNetworkTraffic encapsulatedByRef;
  private Boolean isActive;


}