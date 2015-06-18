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
require_once dirname(realpath(__FILE__)) .'/constants.php';
require_once dirname(realpath(__FILE__)) .'/class.tacacsplus_header.php';
require_once dirname(realpath(__FILE__)) .'/class.tacacsplus_auth_start.php';
require_once dirname(realpath(__FILE__)) .'/class.tacacsplus_auth_reply.php';
require_once dirname(realpath(__FILE__)) .'/class.tacacsplus_auth_cont.php';

/**
* TacacsPlus_Client represents a TACACS+ Client.
*
* @category Authentication
* @package  TacacsPlus
* @author   Martín Claro <martin.claro@gmail.com>
* @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlus_Client
{
    private $_debug = false;
    private $_addr = '127.0.0.1';
    private $_port = 49;
    private $_secret = 'secretkey';
    private $_socket = null;
    private $_sessionId = 0;
    private $_lastSeqNo = 0;

    public function __construct($debug=false)
    {
        $this->_debug = $debug;
        $this->_log(__CLASS__." created.");
    }

    public function setServer($addr, $port, $token)
    {
        $this->_addr = $addr;
        $this->_port = $port;
        $this->_secret = $token;
    }

    public function authenticate($username, $password, $port="", $addr="")
    {
        mt_srand();
        $this->_sessionId = mt_rand(1, (pow(2, 16)-1));
        $this->_lastSeqNo = 0;

        //--- START ------------------------------------------------------------
        $in = null;

        $start = new TacacsPlus_AuthStart();
        $start->_action         = TAC_PLUS_AUTHEN_LOGIN;
        $start->_privLevel      = TAC_PLUS_PRIV_LVL_USER;
        $start->_authen_type    = TAC_PLUS_AUTHEN_TYPE_PAP;
        $start->_service        = TAC_PLUS_AUTHEN_SVC_NONE;
        $start->_user           = $username;
        $start->_port           = strtolower($port);
        $start->_remoteAddr     = inet_pton($addr);
        $start->_data           = $password;
        $bin_start = $start->toBinary();

        $hdr = new TacacsPlus_PacketHeader();
        $hdr->_version = TAC_PLUS_VER_1;
        $hdr->setSequenceNumber(($this->_lastSeqNo + 1));
        $hdr->_sessionId = $this->_sessionId;
        $hdr->setData($bin_start);
        $bin_hdr = $hdr->toBinary();

        $pad = $hdr->getPseudoPad($this->_secret);
        $in = $bin_hdr . ( $bin_start ^ $pad );

        $this->_send($in);

        //--- REPLY ------------------------------------------------------------
        $out = $this->_recv();


        $bin_hdr = substr($out, 0, TAC_PLUS_HDR_SIZE);
        $hdr = new TacacsPlus_PacketHeader($bin_hdr);
        $this->_lastSeqNo = $hdr->getSequenceNumber();
        $pad = $hdr->getPseudoPad($this->_secret);

        $bin_reply = substr($out, TAC_PLUS_HDR_SIZE);
        $reply = new TacacsPlus_AuthReply(($bin_reply ^ $pad));

        if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_PASS) {
            return true;

        } else if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_ERROR) {
            return false;

        } else if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_FAIL) {
            return false;

        } else if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_GETPASS) {

            //--- CONT ---------------------------------------------------------
            $in = null;


            $cont = new TacacsPlus_AuthCont();
            $bin_cont = $cont->toBinary();

            $hdr = new TacacsPlus_PacketHeader();
            $hdr->_version = TAC_PLUS_VER_0;
            $hdr->setSequenceNumber(($this->_lastSeqNo + 1));
            $hdr->_sessionId = $this->_sessionId;
            $hdr->_dataLen = strlen($bin_start);

            $bin_hdr = $hdr->toBinary();
            $pad = $hdr->getPseudoPad($this->_secret);
            $in = $bin_hdr . ( $bin_cont ^ $pad );

            $this->_send($in);

            //--- REPLY --------------------------------------------------------
            $out = $this->_recv();

            $bin_hdr = substr($out, 0, TAC_PLUS_HDR_SIZE);
            $hdr = new TacacsPlus_PacketHeader($bin_hdr);

            $pad = $hdr->getPseudoPad($this->_secret);

            $bin_reply = substr(
                $out,
                TAC_PLUS_HDR_SIZE
            );
            $reply = new TacacsPlus_AuthReply(($bin_reply ^ $pad));

        }

    }

    public function connect()
    {
        $this->_socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->_socket === false) {
            $this->_log(
                "socket_create() failed: reason: " .
                socket_strerror(socket_last_error()) . ""
            );
            return false;
        }

        $result = socket_connect($this->_socket, $this->_addr, $this->_port);
        if ($result === false) {
            $this->_log(
                "socket_connect() failed: reason: ($result) " .
                socket_strerror(socket_last_error($this->_socket)) . ""
            );
            return false;
        }

        return true;
    }

    public function disconnect()
    {
        @socket_close($this->_socket);
        $this->_log("Disconnected!");
    }

    public function setDebug($val=true)
    {
        $this->_debug = $val;
    }

    private function _send($data)
    {
        $this->_log("Sending TACACS+ message... ");
        socket_write($this->_socket, $data, strlen($data));
        $this->_log("SENT: ". print_r(unpack("H*", $data)[1], true) ."");
    }

    private function _recv()
    {
        $this->_log("Reading TACACS+ response... ");
        $out = null;
        $bytes = 0;
        if (false !== ($bytes = socket_recv(
            $this->_socket, $out,
            2048, MSG_WAITALL
        ))) {
            $this->_log("DONE (read $bytes bytes)!");
        } else {
            $this->_log("ERROR READING SOCKET!");
        }
        $this->_log("RECV: ". print_r(unpack("H*", $out)[1], true) ."");
        return $out;
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