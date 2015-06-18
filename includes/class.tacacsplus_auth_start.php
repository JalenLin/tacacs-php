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
    private $_debug = false;
    public $_action         = TAC_PLUS_AUTHEN_LOGIN;
    public $_privLevel      = TAC_PLUS_PRIV_LVL_USER;
    public $_authen_type    = TAC_PLUS_AUTHEN_TYPE_PAP;
    public $_service        = TAC_PLUS_AUTHEN_SVC_LOGIN;
    public $_user_len       = 0;
    public $_port_len       = 0;
    public $_r_addr_len     = 0;
    public $_data_len       = 0;
    public $_user           = '';
    public $_port           = '';
    public $_remoteAddr     = '';
    public $_data           = '';

    public function __construct()
    {
        $this->_action = TAC_PLUS_AUTHEN_LOGIN;
    }

    public function toBinary()
    {
        $this->_calculate();
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

    public function setDebug($val=true)
    {
        $this->_debug = $val;
    }

    private function _calculate()
    {
        $this->_user_len    = strlen($this->_user);
        $this->_port_len    = strlen($this->_port);
        $this->_r_addr_len  = strlen($this->_remoteAddr);
        $this->_data_len    = strlen($this->_data);
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
