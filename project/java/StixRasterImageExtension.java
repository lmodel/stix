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
  The Raster Image file extension specifies a default extension for capturing properties specific to image files.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixRasterImageExtension  {

  private Integer imageHeight;
  private Integer imageWidth;
  private Integer bitsPerPixel;
  private StixExifTags exifTags;


}