<?php
/**
* Tacacs_Client is a sample TACACS+ client for authentication purposes.
*
* This source code is provided as a demostration for TACACS+ authentication.
*
* @category Authentication
* @package  TACACS_Client
* @author   Martín Claro <martin.claro@gmail.com>
* @license  GNU General Public License
* @version  1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/

error_reporting(E_ALL);
set_time_limit(0);
ob_implicit_flush();

// VERSION
define('TAC_PLUS_MAJOR_VER_MASK', 0xf0);
define('TAC_PLUS_MAJOR_VER',      0xc0);
define('TAC_PLUS_MINOR_VER_0',    0x00);
define('TAC_PLUS_VER_0',          (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_0));
define('TAC_PLUS_MINOR_VER_1',    0x01);
define('TAC_PLUS_VER_1',          (TAC_PLUS_MAJOR_VER | TAC_PLUS_MINOR_VER_1));

// TYPE
define('TAC_PLUS_AUTHEN',   0x01);
define('TAC_PLUS_AUTHOR',   0x02);
define('TAC_PLUS_ACCT',     0x03);

// FLAGS
define('TAC_PLUS_ENCRYPTED_FLAG',       0x00);  /* packet is encrypted */
define('TAC_PLUS_UNENCRYPTED_FLAG',     0x01);  /* packet is unencrypted */
define('TAC_PLUS_SINGLE_CONNECT_FLAG',  0x04);  /* multiplexing supported */

// ACTION
define('TAC_PLUS_AUTHEN_LOGIN',     0x01);
define('TAC_PLUS_AUTHEN_CHPASS',    0x02);
define('TAC_PLUS_AUTHEN_SENDPASS',  0x03); /* deprecated */
define('TAC_PLUS_AUTHEN_SENDAUTH',  0x04);

// PRIV LEVELS
define('TAC_PLUS_PRIV_LVL_MIN',     0x00);
define('TAC_PLUS_PRIV_LVL_MAX',     0x0f);
define('TAC_PLUS_PRIV_LVL_USER',    0x01);
define('TAC_PLUS_PRIV_LVL_ROOT',    0x0f);

// AUTH TYPES
define('TAC_PLUS_AUTHEN_TYPE_ASCII',    0x01);
define('TAC_PLUS_AUTHEN_TYPE_PAP',      0x02);
define('TAC_PLUS_AUTHEN_TYPE_CHAP',     0x03);
define('TAC_PLUS_AUTHEN_TYPE_ARAP',     0x04);
define('TAC_PLUS_AUTHEN_TYPE_MSCHAP',   0x05);

// SERVICES
define('TAC_PLUS_AUTHEN_SVC_NONE',      0x00);
define('TAC_PLUS_AUTHEN_SVC_LOGIN',     0x01);
define('TAC_PLUS_AUTHEN_SVC_ENABLE',    0x02);
define('TAC_PLUS_AUTHEN_SVC_PPP',       0x03);
define('TAC_PLUS_AUTHEN_SVC_ARAP',      0x04);
define('TAC_PLUS_AUTHEN_SVC_PT',        0x05);
define('TAC_PLUS_AUTHEN_SVC_RCMD',      0x06);
define('TAC_PLUS_AUTHEN_SVC_X25',       0x07);
define('TAC_PLUS_AUTHEN_SVC_NASI',      0x08);
define('TAC_PLUS_AUTHEN_SVC_FWPROXY',   0x09);

define('TAC_PLUS_CONTINUE_FLAG_ABORT',  0x01);

// AUTHENTICATION STATUS
define('TAC_PLUS_AUTHEN_STATUS_PASS',       0x01);
define('TAC_PLUS_AUTHEN_STATUS_FAIL',       0x02);
define('TAC_PLUS_AUTHEN_STATUS_GETDATA',    0x03);
define('TAC_PLUS_AUTHEN_STATUS_GETUSER',    0x04);
define('TAC_PLUS_AUTHEN_STATUS_GETPASS',    0x05);
define('TAC_PLUS_AUTHEN_STATUS_RESTART',    0x06);
define('TAC_PLUS_AUTHEN_STATUS_ERROR',      0x07);
define('TAC_PLUS_AUTHEN_STATUS_FOLLOW',     0x21);

define('TAC_PLUS_AUTHEN_FLAG_NOECHO',       0x01);

// SIZES
define('TAC_PLUS_HDR_SIZE',                     12);
define('TAC_AUTHEN_START_FIXED_FIELDS_SIZE',    8);
define('TAC_AUTHEN_CONT_FIXED_FIELDS_SIZE',     5);
define('TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE',    6);

/**
* TacacsPlusPacketHeader represents a TACACS+ Packet Header.
*
* @category Authentication
* @package  TACACS_Client
* @author   Martín Claro <martin.claro@gmail.com>
* @license  GNU General Public License
* @version  Release: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlusPacketHeader
{
    private $_debug = false;
    public $_version = TAC_PLUS_VER_1;
    public $_type = TAC_PLUS_AUTHEN;
    public $_seqNo = 0;
    public $_flags = 0;
    public $_sessionId = 0;
    public $_dataLen = 0;
    private $_data = null;
    private $_pseudoPad = null;
    private $_isEncrypted = true;

    public function __construct($binaryData=null)
    {
        if (!is_null($binaryData) && strlen($binaryData)>TAC_PLUS_HDR_SIZE) {
            // Decode from data
            $tmp = unpack(
                'C1version/C1type/C1seq_no/C1flags/N1session_id/N1data_len',
                substr($binaryData, 0, TAC_PLUS_HDR_SIZE)
            );
            $this->_version     = $tmp['version'];
            $this->_type        = $tmp['type'];
            $this->_seqNo       = $tmp['seq_no'];
            $this->_flags       = $tmp['flags'];
            $this->_sessionId   = $tmp['session_id'];
            $this->_dataLen     = $tmp['data_len'];
            $mask = $this->_flags & TAC_PLUS_UNENCRYPTED_FLAG;
            if ($mask == TAC_PLUS_UNENCRYPTED_FLAG
            ) {
                $this->_log("INFO: TAC_PLUS_UNENCRYPTED_FLAG enabled.");
                $this->_isEncrypted = false;
            } else {
                $this->_log("INFO: TAC_PLUS_UNENCRYPTED_FLAG disabled.");
                $this->_isEncrypted = true;
            }
            $this->_log(print_r($this, true));

        } else {
            // Create from scratch
            $this->_seqNo = 1;
            $this->_flags = TAC_PLUS_SINGLE_CONNECT_FLAG;
        }
    }

    public function setData($binaryData)
    {
        $this->_data = $binaryData;
    }

    public function getPseudoPad($secret)
    {
        $this->_pseudoPad = hash(
            'md5',
            pack(
                'Na*CC',
                $this->_sessionId,
                $secret,
                $this->_version,
                $this->_seqNo
            ),
            true
        );
        while (strlen($this->_pseudoPad) < $this->_dataLen) {
            $this->_pseudoPad = $this->_pseudoPad .
                                hash(
                                    'md5',
                                    pack(
                                        'Na*CC',
                                        $this->_sessionId,
                                        $secret,
                                        $this->_version,
                                        $this->_seqNo
                                    ) .
                                    $this->_pseudoPad,
                                    true
                                );
        }

        $this->_pseudoPad = substr($this->_pseudoPad, 0, $this->_dataLen);
        $this->_log(print_r($this, true));
        return $this->_pseudoPad;
    }

    public function toBinary()
    {
        $this->_calculate();
        $this->_log(print_r($this, true));
        return pack(
            'CCCCNN', $this->_version,
            $this->_type,
            $this->_seqNo,
            $this->_flags,
            $this->_sessionId,
            $this->_dataLen
        );
    }

    public function setDebug($val=true)
    {
        $this->_debug = $val;
    }

    private function _calculate()
    {
        $this->_dataLen = strlen($this->_data);
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

/**
* TacacsPlusPacketHeader represents a TACACS+ START Message.
*
* @category Authentication
* @package  TACACS_Client
* @author   Martín Claro <martin.claro@gmail.com>
* @license  GNU General Public License
* @version  Release: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlusAuthStart
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

/**
* TacacsPlusPacketHeader represents a TACACS+ CONT Message.
*
* @category Authentication
* @package  TACACS_CLient
* @author   Martín Claro <martin.claro@gmail.com>
* @license  GNU General Public License
* @version  Release: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlusAuthCont
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

/**
* TacacsPlusPacketHeader represents a TACACS+ REPLY Message.
*
* @category Authentication
* @package  TACACS_CLient
* @author   Martín Claro <martin.claro@gmail.com>
* @license  GNU General Public License
* @version  Release: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlusAuthReply
{
    private $_debug = false;
    private $_status = 0;
    private $_flags = 0;
    private $_msg_len = 0;
    private $_data_len = 0;
    private $_msg = null;
    private $_data = null;

    public function __construct($binaryData=null)
    {
        if (!is_null($binaryData) && strlen($binaryData)>=TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE) {
            $ptr = 0;
            $reply = unpack(
                'C1status/C1flags/n1server_msg_len/n1data_len',
                substr($binaryData, $ptr, TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE)
            );
            $this->_status      = $reply['status'];
            $this->_flags       = $reply['flags'];
            $this->_msg_len     = $reply['server_msg_len'];
            $this->_data_len    = $reply['data_len'];

            if ($this->_msg_len > 0) {
                $ptr += TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE;
                $this->_msg = unpack(
                    'a*', substr(
                        $binaryData,
                        $ptr,
                        $this->_msg_len
                    )
                )[1];
            }
            if ($this->_data_len > 0) {
                $ptr += $this->_msg_len;
                $this->_data = unpack(
                    'a*', substr(
                        $binaryData,
                        $ptr, $this->_data_len
                    )
                )[1];
            }
        }
        $this->_log(print_r($this, true));
    }

    public function getStatus()
    {
        return $this->_status;
    }

    public function setDebug($val=true)
    {
        $this->_debug = $val;
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

/**
* TacacsPlusPacketHeader represents a TACACS+ Server.
*
* @category Authentication
* @package  TACACS_Client
* @author   Martín Claro <martin.claro@gmail.com>
* @license  GNU General Public License
* @version  Release: 1.0.0
* @access   public
* @link     https://github.com/martinclaro
*/
class TacacsPlusServer
{
    private $_debug = false;
    private $_addr = '127.0.0.1';
    private $_port = 49;
    private $_secret = 'secretkey';
    private $_socket = null;
    private $_sessionId = 0;

    public function __construct($debug=false)
    {
        $this->_debug = $debug;
        $this->_log("TacacsPlusServer created.");
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
        $this->_sessionId = mt_rand(1, (pow(2, 32)-1));

        //--- START ------------------------------------------------------------
        $in = null;

        $start = new TacacsPlusAuthStart();
        $start->_action         = TAC_PLUS_AUTHEN_LOGIN;
        $start->_privLevel      = TAC_PLUS_PRIV_LVL_USER;
        $start->_authen_type    = TAC_PLUS_AUTHEN_TYPE_PAP;
        $start->_service        = TAC_PLUS_AUTHEN_SVC_NONE;
        $start->_user           = $username;
        $start->_port           = strtolower($port);
        $start->_remoteAddr     = inet_pton($addr);
        $start->_data           = $password;
        $bin_start = $start->toBinary();

        $hdr = new TacacsPlusPacketHeader();
        $hdr->_version = TAC_PLUS_VER_1;
        $hdr->_seqNo = 1;
        $hdr->_sessionId = $this->_sessionId;
        $hdr->setData($bin_start);
        $bin_hdr = $hdr->toBinary();

        $pad = $hdr->getPseudoPad($this->_secret);
        $in = $bin_hdr . ( $bin_start ^ $pad );

        $this->_send($in);

        //--- REPLY ------------------------------------------------------------
        $out = $this->_recv();

        $bin_hdr = substr($out, 0, TAC_PLUS_HDR_SIZE);
        $hdr = new TacacsPlusPacketHeader($bin_hdr);
        $pad = $hdr->getPseudoPad($this->_secret);

        $bin_reply = substr($out, TAC_PLUS_HDR_SIZE);
        $reply = new TacacsPlusAuthReply(($bin_reply ^ $pad));

        if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_PASS) {
            return true;

        } else if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_ERROR) {
            return false;

        } else if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_FAIL) {
            return false;

        } else if ($reply->getStatus() == TAC_PLUS_AUTHEN_STATUS_GETPASS) {

            //--- CONT ---------------------------------------------------------
            $in = null;

            $cont = new TacacsPlusAuthCont();
            $bin_cont = $cont->toBinary();

            $hdr = new TacacsPlusPacketHeader();
            $hdr->_version = TAC_PLUS_VER_0;
            $hdr->_seqNo = ($hdr->_seqNo + 2);
            $hdr->_sessionId = $this->_sessionId;
            $hdr->_dataLen = strlen($bin_start);

            $bin_hdr = $hdr->toBinary();
            $pad = $hdr->getPseudoPad($this->_secret);
            $in = $bin_hdr . ( $bin_cont ^ $pad );

            $this->_send($in);

            //--- REPLY --------------------------------------------------------
            $out = $this->_recv();

            $bin_hdr = substr($out, 0, TAC_PLUS_HDR_SIZE);
            $hdr = new TacacsPlusPacketHeader($bin_hdr);

            $pad = $hdr->getPseudoPad($this->_secret);

            $bin_reply = substr(
                $out,
                TAC_PLUS_HDR_SIZE,
                TAC_AUTHEN_REPLY_FIXED_FIELDS_SIZE
            );
            $reply = new TacacsPlusAuthReply(($bin_reply ^ $pad));

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

// RUNTIME
$tacacs_server_addr         ='192.168.197.150';
$tacacs_server_port         = 49;
$tacacs_server_secret       = 'testing123';

$tacacs_user_username       = 'testuser';
$tacacs_user_password       = 'test1234';
$tacacs_user_port           = 'http';
$tacacs_user_remote_addr    = '192.168.197.122';

$srv = new TacacsPlusServer(true);
$srv->setServer(
    $tacacs_server_addr,
    $tacacs_server_port,
    $tacacs_server_secret
);
$srv->connect();
$res = $srv->authenticate(
    $tacacs_user_username,
    $tacacs_user_password,
    $tacacs_user_port,
    $tacacs_user_remote_addr
);
if ($res) {
    echo "\nAUTHENTICATION SUCCESS!\n\n";
} else {
    echo "\nAUTHENTICATION FAILED!\n\n";
}
$srv->disconnect();

