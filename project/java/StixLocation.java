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
  A geographic location, given as a region, a civic address, a latitude and longitude, or any mix of them.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixLocation extends StixDomainObject {

  private String description;
  private String name;
  private Float latitude;
  private Float longitude;
  private Float precision;
  private String region;
  private String country;
  private String administrativeArea;
  private String city;
  private String streetAddress;
  private String postalCode;


}