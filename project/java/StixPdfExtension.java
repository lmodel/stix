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
  The PDF file extension specifies a default extension for capturing properties specific to PDF files.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixPdfExtension  {

  private String version;
  private Boolean isOptimized;
  private StixPdfDocumentInfo documentInfoDict;
  private String pdfid0;
  private String pdfid1;


}