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
  The Windows PE Binary File extension specifies a default extension for capturing properties specific to Windows portable executable (PE) files.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixWindowsPeBinaryExtension  {

  private String peType;
  private String imphash;
  private String machineHex;
  private Integer numberOfSections;
  private ZonedDateTime timeDateStamp;
  private String pointerToSymbolTableHex;
  private Integer numberOfSymbols;
  private Integer sizeOfOptionalHeader;
  private String characteristicsHex;
  private StixHashes fileHeaderHashes;
  private StixWindowsPeOptionalHeader optionalHeader;
  private List<StixWindowsPeSection> sections;


}