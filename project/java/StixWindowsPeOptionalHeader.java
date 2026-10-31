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
  The optional header of a Windows PE binary.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixWindowsPeOptionalHeader  {

  private String magicHex;
  private Integer majorLinkerVersion;
  private Integer minorLinkerVersion;
  private Integer sizeOfCode;
  private Integer sizeOfInitializedData;
  private Integer sizeOfUninitializedData;
  private Integer addressOfEntryPoint;
  private Integer baseOfCode;
  private Integer baseOfData;
  private Integer imageBase;
  private Integer sectionAlignment;
  private Integer fileAlignment;
  private Integer majorOsVersion;
  private Integer minorOsVersion;
  private Integer majorImageVersion;
  private Integer minorImageVersion;
  private Integer majorSubsystemVersion;
  private Integer minorSubsystemVersion;
  private String win32VersionValueHex;
  private Integer sizeOfImage;
  private Integer sizeOfHeaders;
  private String checksumHex;
  private String subsystemHex;
  private String dllCharacteristicsHex;
  private Integer sizeOfStackReserve;
  private Integer sizeOfStackCommit;
  private Integer sizeOfHeapReserve;
  private Integer sizeOfHeapCommit;
  private String loaderFlagsHex;
  private Integer numberOfRvaAndSizes;
  private StixHashes hashes;


}