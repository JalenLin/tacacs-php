<?php

/**
* Tacacs_Client is a sample TACACS+ client for authentication purposes.
*
* This source code is provided as a demostration for TACACS+ authentication.
*
* PHP version 5
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @version  GIT: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/

/**
* TacacsPlus_AuthStart represents a TACACS+ START Message.
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlus_AuthStart
{
    private $_debug         = false;
    private $_action        = TAC_PLUS_AUTHEN_LOGIN;
    private $_privLevel     = TAC_PLUS_PRIV_LVL_USER;
    private $_authen_type   = TAC_PLUS_AUTHEN_TYPE_PAP;
    private $_service       = TAC_PLUS_AUTHEN_SVC_LOGIN;
    private $_user_len      = 0;
    private $_port_len      = 0;
    private $_r_addr_len    = 0;
    private $_data_len      = 0;
    private $_user          = '';
    private $_port          = '';
    private $_remoteAddr    = '';
    private $_data          = '';

    public function __construct()
    {
        $this->_action = TAC_PLUS_AUTHEN_LOGIN;
    }

    public function setAction($val=TAC_PLUS_AUTHEN_LOGIN)
    {
        $this->_action = $val;
    }

    public function setPrivLevel($val=TAC_PLUS_PRIV_LVL_USER)
    {
        $this->_privLevel = $val;
    }

    public function setAuthenticationType($val=TAC_PLUS_AUTHEN_TYPE_PAP)
    {
        $this->_authen_type = $val;
    }

    public function setService($val=TAC_PLUS_AUTHEN_SVC_LOGIN)
    {
        $this->_service = $val;
    }

    public function setUsername($val=null)
    {
        $this->_user = $val;
        $this->_user_len = strlen($this->_user);
    }

    public function setPort($val=null)
    {
        $this->_port = $val;
        $this->_port_len = strlen($this->_port);
    }

    public function setRemoteAddress($val=null)
    {
        $this->_remoteAddr = $val;
        $this->_r_addr_len = strlen($this->_remoteAddr);
    }

    public function setData($val=null)
    {
        $this->_data = $val;
        $this->_data_len = strlen($this->_data);
    }

    public function setDebug($val=true)
    {
        $this->_debug = $val;
    }

    public function toBinary()
    {
        $this->_log(print_r($this, true));
        $bin = pack(
            'CCCCCCCC', $this->_action,
            $this->_privLevel,
            $this->_authen_type,
            $this->_service,
            $this->_user_len,
            $this->_port_len,
            $this->_r_addr_len,
            $this->_data_len
        );
        if ($this->_user_len > 0) {
            $bin .= pack('a*', $this->_user);
        }
        if ($this->_port_len > 0) {
            $bin .= pack('a*', $this->_port);
        }
        if ($this->_r_addr_len > 0) {
            $bin .= pack('a*', $this->_remoteAddr);
        }
        if ($this->_data_len > 0) {
            $bin .= pack('a*', $this->_data);
        }
        return $bin;
    }

    private function _log($obj="")
    {
        if ($this->_debug) {
            echo "DEBUG: ";
            if (is_string($obj)) {
                echo $obj;
            } else {
                echo print_r($obj, true);
            }
            echo "\n";
        }
    }
}
