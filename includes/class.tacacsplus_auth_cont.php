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
* TacacsPlus_AuthCont represents a TACACS+ CONT Message.
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlus_AuthCont
{
    private $_debug = false;
    private $_user_msg_len = 0;
    private $_user_data_len = 0;
    private $_flags = 0;
    private $_usr_msg = null;
    private $_user_data = null;

    public function toBinary()
    {
        $this->_calculate();
        $this->_log(print_r($this, true));
        $bin = pack(
            'NNC',
            $this->_user_msg_len,
            $this->_user_data_len,
            $this->_flags
        );
        if ($this->_user_msg_len > 0) {
            $bin .= pack('a*', $this->_usr_msg);
        }
        if ($this->_user_data_len > 0) {
            $bin .= pack('a*', $this->_user_data);
        }
        return $bin;
    }

    private function _calculate()
    {
        $this->_user_msg_len    = strlen($this->_usr_msg);
        $this->_user_data_len    = strlen($this->_user_data);
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

