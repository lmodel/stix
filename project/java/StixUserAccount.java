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
  The User Account Object represents an instance of any type of user account, including but not limited to operating system, device, messaging service, and social media platform accounts.
**/
@Data
@EqualsAndHashCode(callSuper=false)
public class StixUserAccount extends StixCyberObservableObject {

  private String userId;
  private String credential;
  private String accountLogin;
  private String accountType;
  private String displayName;
  private Boolean isServiceAccount;
  private Boolean isPrivileged;
  private Boolean canEscalatePrivs;
  private Boolean isDisabled;
  private ZonedDateTime accountCreated;
  private ZonedDateTime accountExpires;
  private ZonedDateTime credentialLastChanged;
  private ZonedDateTime accountFirstLogin;
  private ZonedDateTime accountLastLogin;


}