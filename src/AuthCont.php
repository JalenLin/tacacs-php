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
namespace TACACS;
/**
 * AuthCont represents a TACACS+ CONT Message.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @access   public
 * @link     https://github.com/martinclaro
 */
class AuthCont
{
    /**
     * toBinary
     *
     * @return string
     */
    public function toBinary()
    {
        $userMsg = null;
        $userData = null;

        $userMsgLen = strlen($userMsg);
        $userDataLen = strlen($userData);

        $flags = 0;

        $this->_log(print_r($this, true));
        $bin = pack(
            'NNC',
            $userMsgLen,
            $userDataLen,
            $flags
        );
        if ($userMsgLen > 0) {
            $bin .= pack('a*', $userMsg);
        }
        if ($userDataLen > 0) {
            $bin .= pack('a*', $userData);
        }
        return $bin;
    }

    /**
     * Log
     *
     * @param mixed $obj The record to log
     *
     * @return void
     */
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

