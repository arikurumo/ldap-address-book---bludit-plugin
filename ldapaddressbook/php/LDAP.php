<?php
/**
 * Get a list of users from Active Directory.
 */

class LDAP {

  private $ldap_connection = false;
  public $connected = false;
  public $Entries = array();
  public $Error = false;

  public function __construct($ldap_host, $ldap_protocol_version = 3) {
     $this->ldap_connection = ldap_connect($ldap_host);
     if (false === $this->ldap_connection){
        $this->Error = 'Cannot connect LDAP server!';
        return false;
     } else {
        // We have to set this option for the version of Active Directory we are using.
        if (false === ldap_set_option($this->ldap_connection, LDAP_OPT_PROTOCOL_VERSION, $ldap_protocol_version)) {
           $this->Error = 'Cannot set protocol ver.'.$ldap_protocol_version.' for LDAP connection!';
           return false;
        }
        ldap_set_option($this->ldap_connection, LDAP_OPT_REFERRALS, 0); // We need this for doing an LDAP search.
        $this->connected = true;
        return true;
     }
  }

  // Binary to SID
  private function bin_to_str_sid($binary_sid) {
     $sid = NULL;
     // Get revision, indentifier, authority 
     $parts = unpack('Crev/x/nidhigh/Nidlow', $binary_sid);
     // Set revision, indentifier, authority 
     $sid = sprintf('S-%u-%d',  $parts['rev'], ($parts['idhigh']<<32) + $parts['idlow']);
     // Translate domain
     $parts = unpack('x8/V*', $binary_sid);
     // Append if parts exists
     if ($parts) $sid .= '-';
     // Join all
     $sid .= join('-', $parts);
     return $sid;
  }

  public function bind($ldap_username, $ldap_password) {
     set_error_handler(function($errno, $errstr, $errfile, $errline) { if (0 === error_reporting()) { return false; } throw new ErrorException($errstr, 0, $errno, $errfile, $errline); });
     try {
        $bind = ldap_bind($this->ldap_connection, $ldap_username, $ldap_password);
        if ($bind) {
           $this->connected = true;
           return true;
        }
     } catch (ErrorException $e) {
        $this->Error = $e->getMessage();
        $this->connected = false;
        return false;
     } 
  }
  
  public function testSearch($ldap_base_dn, $search_filter) {
     if (!$this->connected) {
        $this->Error = 'Not connection to server!';
        return false;
     }
     try {
        $result = ldap_search($this->ldap_connection, $ldap_base_dn, $search_filter);
     } catch (ErrorException $e) {
        $this->Error = $e->getMessage();
        return false;
     }
     return true;
  }
  
  public function GetEntries($ldap_username, $ldap_password, $ldap_base_dn, $search_filter, $Attributes=array()) {

     if (!$this->connected) return false;

     $ExcludedValues = array();
     $MustExistsValues = array();
     foreach ($Attributes as $Key => $Value) {
        if (!is_numeric($Key)) {
           if ($Key[0] == '!') {
              $Key = substr($Key, 1);
              $ExcludedValues[$Key] = !is_array($Value) ? array($Value) : $Value;
           } else {
              $MustExistsValues[$Key] = !is_array($Value) ? array($Value) : $Value;
           } 
           unset($Attributes[$Key]);
           $Attributes[] = $Key;
        }
     }
     $Result = $this->testSearch($ldap_base_dn, $search_filter) ? ldap_search($this->ldap_connection, $ldap_base_dn, $search_filter, $Attributes) : false;
     if (false !== $Result) {
        $Entries = ldap_get_entries($this->ldap_connection, $Result);
        if (isset($Entries['count'])) unset($Entries['count']);
        foreach ($Entries as $Entry) {
           $ValuesForComparsion = array_intersect_key($ExcludedValues, $Entry);
           foreach ($ValuesForComparsion as $Key) {
              if ($ExcludedValues[$Key] == $Entry[$Key]) continue 2; // Excluded value - stop proceccing and go to next entry
           }
           $ValuesForComparsion = array_intersect_key($MustExistsValues, $Entry);
           foreach ($ValuesForComparsion as $Key) {
              if ($ExcludedValues[$Key] != $Entry[$Key]) continue 2; // Included value not equal - stop proceccing and go to next entry
           }
           $Item = array();
           foreach ($Attributes as $Attribute) {
              $origAttr = $Attribute;
              if (!isset($Entry[$Attribute])) $Attribute = strtolower($Attribute);
              if (!isset($Entry[$Attribute])) {
                 $Item[$origAttr] = '';
              } elseif (isset($Entry[$Attribute]['count'])) {
                 if ($Entry[$Attribute]['count'] == 1) {
                    $Item[$origAttr] = ('objectsid' == $Attribute) ? $this->bin_to_str_sid($Entry[$Attribute][0]) : $Entry[$Attribute][0];
                 } elseif ($Entry[$Attribute]['count'] > 1) {
                    unset($Entry[$Attribute]['count']);
                    $Item[$origAttr] = $Entry[$Attribute];
                    if ('objectsid' == $Attribute) {
                       foreach ($Item[$Attribute] as &$SidBin) {
                          $SidBin = $this->bin_to_str_sid($SidBin);
                       }
                    }
                 } else {
                    $Item[$origAttr] = $Entry[$Attribute];
                 } 
              } else {
                 $Item[$origAttr] = $Entry[$Attribute];
              }
           }
           
           $this->Entries[] = $Item;
           //$this->Entries[] = $Entry;
           //$ad_users[strtoupper(trim($entries[$x]['samaccountname'][0]))] = array('email' => strtolower(trim($entries[$x]['mail'][0])),'first_name' => trim($entries[$x]['givenname'][0]),'last_name' => trim($entries[$x]['sn'][0]));
        }
     }
     ldap_unbind($this->ldap_connection); // Clean up after ourselves.
  }
  
}

?>
