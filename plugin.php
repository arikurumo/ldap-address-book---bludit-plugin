<?php
class ldapaddressbook extends Plugin {
  
  private $ldap;
  private $pass = '6D%ubS2#kX';
  
  public function init() {
    $this->dbFields = array('ldapaddressbook_host' => ''
                           ,'ldapaddressbook_user' => ''
                           ,'ldapaddressbook_password' => ''
                           ,'ldapaddressbook_protocolversion' => ''
                           ,'ldapaddressbook_basedn' => ''
                           ,'ldapaddressbook_searchfilter' => ''
                           ,'ldapaddressbook_attributes' => ''
                           ,'ldapaddressbook_translatedattributes' => ''
                           ,'ldapaddressbook_notshowconditions' => ''
                           ,'ldapaddressbook_wheretoshow' => ''
                           ,'ldapaddressbook_pagewheretoshow' => ''
                           ,'ldapaddressbook_orderby' => ''
                           ,'ldapaddressbook_separator' => ','
                           ,'ldapaddressbook_sortorder' => 'asc'
		                       );
  }

  public function siteHead() {
    echo '<link rel="stylesheet" href="'.$this->domainPath().'css/ldapaddressbook.css">';
  }

  private function startConnectionLDAP() {
    global $L;
    
    $errorText = '';
    if (!file_exists($this->phpPath().'php/LDAP.php')) {
		   $errorText .= $L->get('Class').' <b>LDAP</b> '.$L->get('is not defined').'.<br>';
    } else {
       include($this->phpPath().'php/LDAP.php');
       if (!class_exists('LDAP')) {
          $errorText .= $L->get('Class').' <b>LDAP</b> '.$L->get('is not defined').'.<br>';
       } else {
          $this->ldap = new LDAP($this->getValue('ldapaddressbook_host'), $this->getValue('ldapaddressbook_protocolversion'));
          if (false === $this->ldap) {
             $errorText .= $this->ldap->Error.'<br>';
          } else {
             if (false === $this->ldap->bind($this->getValue('ldapaddressbook_user'), (extension_loaded('openssl') ? (empty($this->getValue('ldapaddressbook_password')) ? '' : openssl_decrypt($this->getValue('ldapaddressbook_password'), "AES-128-ECB", $this->pass)) : $this->getValue('ldapaddressbook_password')))) {
                $errorText .= $this->ldap->Error.'<br>';
             }
          }
       }
    }
    return empty($errorText) ? true : $errorText;
  }
  
  private function getLDAPEntries() {
     if (true === $this->startConnectionLDAP()) {
        $attributes = array_map('trim', explode($this->getValue('ldapaddressbook_separator'), $this->getValue('ldapaddressbook_attributes')));
        $attributesNotShow = array_map(function($v) { return trim(explode('=', $v)[0]); }, explode($this->getValue('ldapaddressbook_separator'), $this->getValue('ldapaddressbook_notshowconditions'))); // add attribures from 'ldapaddressbook_notshowconditions' - for testing bellow
        $attributes = array_unique(array_merge($attributes, $attributesNotShow));
        $this->ldap->GetEntries($this->getValue('ldapaddressbook_user'), (extension_loaded('openssl') ? (empty($this->getValue('ldapaddressbook_password')) ? '' : openssl_decrypt($this->getValue('ldapaddressbook_password'), "AES-128-ECB", $this->pass)) : $this->getValue('ldapaddressbook_password')), $this->getValue('ldapaddressbook_basedn'), html_entity_decode($this->getValue('ldapaddressbook_searchfilter')), $attributes); // $ldap_username, $ldap_password, $ldap_base_dn, $search_filter, $Attributes=array()
        foreach ($this->ldap->Entries as $key => $LdapEntry) {
           $notShowConditions = explode($this->getValue('ldapaddressbook_separator'), $this->getValue('ldapaddressbook_notshowconditions'));
           foreach ($notShowConditions as $notShowCondition) {
              $condition = explode('=', $notShowCondition);
              if (!isset($condition[1])) continue; // wrong condition
              if (empty(trim($condition[1]))) {
                 if (empty($LdapEntry[trim($condition[0])])) { // Ignored entry - not show
                    unset($this->ldap->Entries[$key]);
                    continue 2;
                 }
              } elseif (0 === strpos($LdapEntry[trim($condition[0])], trim($condition[1]))) { // Ignored entry - not show
                 unset($this->ldap->Entries[$key]);
                 continue 2;
              }
           }
        }
        return $this->ldap->Entries;
     } else {
        return array();
     }
  }

	public function generateSalt()
	{
		return Text::randomText(SALT_LENGTH);
	}

	public function generatePasswordHash($password, $salt)
	{
		return sha1($password.$salt);
	}

  // Change original post() func to saving password crypted 
	public function post() {
		$args = $_POST;
		foreach ($this->dbFields as $field=>$value) {
			if (isset($args[$field])) {
				if ('ldapaddressbook_password' == $field && extension_loaded('openssl')) { // password input
           if ($args[$field] != $this->db[$field]) { // and password is changed
              $finalValue = (empty($args[$field]) ? '' : openssl_encrypt($args[$field], "AES-128-ECB", $this->pass));
           } else {
              $finalValue = $args[$field];
           }
        } else {
           $finalValue = Sanitize::html( $args[$field] );
				   if ($finalValue==='false') { $finalValue = false; }
				   elseif ($finalValue==='true') { $finalValue = true; }
        }
				settype($finalValue, gettype($value));
				$this->db[$field] = $finalValue;
			}
		}
		return $this->save();
	}

  private function showAddressBook(){
     global $L;
     global $page;
     
     if (!extension_loaded('ldap') || !$page->key()) return; // Page key is not deffined - page not exists

     $entries = $this->getLDAPEntries();
     $attribs = array_map('trim', explode($this->getValue('ldapaddressbook_separator'), $this->getValue('ldapaddressbook_attributes')));
     $attribsTranslated = array_map('trim', explode($this->getValue('ldapaddressbook_separator'), $this->getValue('ldapaddressbook_translatedattributes')));
     // Sort entries
     foreach (array_reverse(array_map('trim', explode($this->getValue('ldapaddressbook_separator'), $this->getValue('ldapaddressbook_orderby')))) as $orderBy) {
        if (empty(array_column($entries, $orderBy))) continue;
        if ('asc' == $this->getValue('ldapaddressbook_sortorder')) {
           array_multisort(array_column($entries, $orderBy), SORT_ASC,  SORT_LOCALE_STRING, $entries);
        } else {
           array_multisort(array_column($entries, $orderBy), SORT_DESC,  SORT_LOCALE_STRING, $entries);
        }
     }
     echo '<table class="la-table" align="center">'."\n";
     echo '<thead class="la-thead">';
     echo '<tr>';
     foreach ($attribs as $key => $attr) {
        echo '<th class="la-th">'.(isset($attribsTranslated[$key]) ? $attribsTranslated[$key] : $L->get($attr)).'</th>';
     }
     echo '</tr>';
     echo '</thead>'."\n";
     echo '<tbody class="la-tbody">'."\n";
     foreach ($entries as $entry) {
        echo '<tr class="la-tr">';
        foreach ($attribs as $attr) {
           echo '<td class="la-td la-'.$attr.'">'.$entry[$attr].'</td>';
        }
        echo '</tr>'."\n";
     }
     echo '</tbody>';
     echo '</table>';
  }

 
  public function pageBegin(){
     if ('begin' == $this->getValue('ldapaddressbook_wheretoshow') && !empty($this->getvalue('ldapaddressbook_pagewheretoshow'))) {
        global $page;
        if ($this->getvalue('ldapaddressbook_pagewheretoshow') == $page->slug()){
           $this->showAddressBook();
        }
     }
  }
  

  public function pageEnd(){
     if ('end' == $this->getValue('ldapaddressbook_wheretoshow') && !empty($this->getvalue('ldapaddressbook_pagewheretoshow'))) {
        global $page;
        if ($this->getvalue('ldapaddressbook_pagewheretoshow') == $page->slug()){
           $this->showAddressBook();
        }
     }
  }


  //settings

    
	public function form() {
	  global $L;

    $html = '<div class="bg-light border p-4"><h4>'.$L->get('How to use it?').'</h4>';
    $html .= '<p class="lead">'.$L->get('This plugin creates a address book obtained by searching using the LDAP protocol from the specified server').'.</p>';
    $html .= '<p>'.$L->get('Put this code on your template where you want to show address book').'</p>';
    $html .= "<code> &lt;?php Theme::plugins('showAddressBook') ?&gt;</code> ".$L->get('or use settings on').' <b>'.$L->get('Show automatic on top or down page').'</b> '.$L->get('input').'.';
    $html .= '</div><br>';

    $errorText = '';
 	  if (!extension_loaded('ldap')) {
		   $errorText .= $L->get('PHP module').' <b>ldap</b> '.$L->get('is not installed').'.<br>';
    } else {
       $testConnection = $this->startConnectionLDAP();
       if (true !== $testConnection) $errorText .= $testConnection;
       if (!$this->ldap->testSearch($this->getValue('ldapaddressbook_basedn'), html_entity_decode($this->getValue('ldapaddressbook_searchfilter')))) $errorText .= $this->ldap->Error;
    }
 	  if (!extension_loaded('openssl')) {
		   $errorText .= $L->get('PHP module').' <b>openssl</b> '.$L->get('is not installed').'.<br>';
    }
    if (!empty($errorText)) {
       $html .= '<div class="bg-danger text-light p-3"><b>'.$L->get('Error').':</b><br>';
 		   error_log('[ERROR] '.$errorText, 0);
       $html .= $errorText.'</div><br>';
    }

    $html .= '<h5 class="mt-4">'.$L->get('LDAP Settings').'</h5>';
    $html .= '<div class="bg-light border p-4">';
    $html .= '<label>'.$L->get('LDAP host').'</label>';
    $html .= '<input type="text" name="ldapaddressbook_host" placeholder="'.$L->get('Enter name or IP address').'" value="'.$this->getValue('ldapaddressbook_host').'">';
    $html .= '<label>'.$L->get('LDAP user').'</label>';
    $html .= '<input type="text" name="ldapaddressbook_user" placeholder="'.$L->get('Enter bind username').'" value="'.$this->getValue('ldapaddressbook_user').'">';
    $html .= '<label>'.$L->get('LDAP password').'</label>';
    $html .= '<input type="password" name="ldapaddressbook_password" placeholder="'.$L->get('Enter password').'" value="'.$this->getValue('ldapaddressbook_password').'">';
    $html .= '<br>'.$L->get('Leave username and password fields empty for anonymous connection.');
    $html .= '<label>'.$L->get('LDAP protocol version').'</label>';
    $html .= '<input type="text" name="ldapaddressbook_protocolversion" placeholder="'.$L->get('Enter LDAP protocol version').'" value="'.$this->getValue('ldapaddressbook_protocolversion').'">';
    $html .= '<label>'.$L->get('LDAP base DN').'</label>';
    $html .= '<input type="text" name="ldapaddressbook_basedn" placeholder="'.$L->get('Enter LDAP base DN').'" value="'.$this->getValue('ldapaddressbook_basedn').'">';
    $html .= '<label>'.$L->get('LDAP search filter').' - '.$L->get('e.g.').' (&(objectCategory=person)(samaccountname=*))</label>';
    $html .= '<input type="text" name="ldapaddressbook_searchfilter" placeholder="'.$L->get('Enter LDAP search filter').'" value="'.$this->getValue('ldapaddressbook_searchfilter').'">';
    $html .= '<label>'.$L->get('LDAP return attributes').' ('.$L->get('separated by').' '.$this->getValue('ldapaddressbook_separator').')';
    $html .= '<input type="text" name="ldapaddressbook_attributes" placeholder="'.$L->get('Enter LDAP return attributes').'" value="'.$this->getValue('ldapaddressbook_attributes').'">';
    $html .= '<label>'.$L->get('Translations of return attributes').' - '.$L->get('will be displayed in the table header on the page').' ('.$L->get('separated by').' '.$this->getValue('ldapaddressbook_separator').')';
    $html .= '<input type="text" name="ldapaddressbook_translatedattributes" placeholder="'.$L->get('Enter translations for return attributes').'" value="'.$this->getValue('ldapaddressbook_translatedattributes').'">';
    $html .= $L->get('Order of attributes will be used as columns order in table on page');
    $html .= '<label>'.$L->get('Conditions for ignoring records').' ('.$L->get('separated by').' '.$this->getValue('ldapaddressbook_separator').') - '.$L->get('e.g.').' name=Tim Old'.$this->getValue('ldapaddressbook_separator').'name=Elen Small'.$this->getValue('ldapaddressbook_separator').'mail=mail@addr.com';
    $html .= '<input type="text" name="ldapaddressbook_notshowconditions" placeholder="'.$L->get('Enter conditions').'" value="'.$this->getValue('ldapaddressbook_notshowconditions').'">';
    $html .= $L->get('If the return values of the records match the specified conditions, they records will not be displayed in the list on the page');
    $html .= "</div><br>";

    $html .= '<h5 class="mt-4">'.$L->get('Other Settings').'</h5>';
    $html .= '<div class="bg-light border p-4">';
    $html .= '<label>'.$L->get('List position').'</label>';
    $html .= '<select name="ldapaddressbook_wheretoshow">';
    $html .= '<option value="disable" '.($this->getValue('ldapaddressbook_wheretoshow')==="disable"?"selected":"").'>'.$L->get('Show only with function in template').'</option>';
    $html .= '<option value="begin" '.($this->getValue('ldapaddressbook_wheretoshow')==="begin"?"selected":"").'>'.$L->get('Begin on page content').'</option>';
    $html .= '<option value="end" '.($this->getValue('ldapaddressbook_wheretoshow')==="end"?"selected":"").'>'.$L->get('End of page content').'</option>';
    $html .= '</select>';
    $html .= '<label>'.$L->get('Write the Friendly URL name (you find correct on page options, seo sections)').'</label>';
		$html .= '<input type="text" name="ldapaddressbook_pagewheretoshow" placeholder="homepage" value="'.$this->getValue('ldapaddressbook_pagewheretoshow').'">';
    $html .= '<label>'.$L->get('Column name(s) for order by').' ('.$L->get('separated by').' '.$this->getValue('ldapaddressbook_separator').')</label>';
		$html .= '<input type="text" name="ldapaddressbook_orderby" placeholder="'.$L->get('Enter column(s) name(s)').'" value="'.$this->getValue('ldapaddressbook_orderby').'">';
    $html .= '<label>'.$L->get('Sort order').'</label>';
    $html .= '<select name="ldapaddressbook_sortorder">';
    $html .= '<option value="asc" '.($this->getValue('ldapaddressbook_sortorder')==="asc"?"selected":"").'>'.$L->get('Ascending').'</option>';
    $html .= '<option value="desc" '.($this->getValue('ldapaddressbook_sortorder')==="desc"?"selected":"").'>'.$L->get('Descending').'</option>';
    $html .= '</select>';
    $html .= '<label>'.$L->get('Separator that will be used to separate the entered values').'</label>';
		$html .= '<input type="text" name="ldapaddressbook_separator" value="'.$this->getValue('ldapaddressbook_separator').'">';
    $html .= "</div>";
              
        
    $html .= '<div class="bg-light col-md-12 mt-5 py-3 d-block border text-center">';
    $html .= '<p class="lead">'.$L->get('Created by').' <b>arikurumo</b> | ❤️ '.$L->get('Buy me a cup of tea').'</p>';
    $html .= '<a href="https://www.paypal.com/donate/?business=TTSV8RYX5ZFAY&no_recurring=0&item_name=Thank+you.+I+appreciate+it+%3B%29&currency_code=EUR">';
    $html .= '<img alt="" border="0" src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif"  />';
    $html .= '</a>';
    $html .= '</div>';
    $html .= '<br>';

    return $html;
  }
}
?>
