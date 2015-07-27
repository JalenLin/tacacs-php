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
 * @link     https://github.com/martinclaro
 */
namespace TACACS;

use Psr\Log\LoggerInterface;
/**
 * Client represents a TACACS+ Client.
 *
 * @category Authentication
 * @package  TacacsPlus
 * @author   Martín Claro <martin.claro@gmail.com>
 * @license  http://www.gnu.org/copyleft/gpl.html GNU General Public License
 * @link     https://github.com/martinclaro
 */
class Client
{
    /**
     * @var LoggerInterface
     */
    protected $logger = null;
    protected $addr = '127.0.0.1';
    protected $port = 49;
    protected $secret = 'secretkey';
    protected $socket = null;
    protected $lastSeqNo = 0;

    /**
     * Class construct
     *
     * @param LoggerInterface $logger The logger
     */
    public function __construct(LoggerInterface $logger = null)
    {
        $this->logger = $logger;

        $this->log(__CLASS__." created.");
    }

    /**
     * Set server
     *
     * @param string $addr  The addr
     * @param string $port  The port
     * @param string $secret The secret
     *
     * @return void
     */
    public function setServer($addr, $port, $secret)
    {
        $this->addr = $addr;
        $this->port = $port;
        $this->secret = $secret;
    }

    /**
     * Authenticate
     *
     * @param string $username The username
     * @param string $password The password
     * @param string $port     The port
     * @param string $addr     The addr
     *
     * @return boolean
     */
    public function authenticate($username, $password, $port = null, $addr = null)
    {
        $this->connect();

        $sessionId = $this->genSessionId();
        $this->lastSeqNo = 1;

        //--- START ------------------------------------------------------------
        $builder = $this->getStartPacketBuilder();
        $builder->setUsername($username);
        $builder->setPassword($password);
        $builder->setPort($port);
        $builder->setRemoteAddress($addr);
        $builder->setSequenceNumber($this->lastSeqNo);
        $builder->setSessionId($sessionId);
        $start = $builder->build();

        $this->send($start->toBinary());

        //--- REPLY ------------------------------------------------------------
        $out = $this->recv();

        $builder = $this->getReplyPacketBuilder();
        $reply = $builder->build();
        $reply->parseBinary($out);

        $this->lastSeqNo = $reply->getHeader()->getSequenceNumber();

        if ($reply->getBody()->getStatus() == TAC_PLUS_AUTHEN_STATUS_PASS) {
            return true;

        } else if ($reply->getBody()->getStatus() == TAC_PLUS_AUTHEN_STATUS_ERROR) {
            return false;

        } else if ($reply->getBody()->getStatus() == TAC_PLUS_AUTHEN_STATUS_FAIL) {
            return false;

        } else if ($reply->getBody()->getStatus() == TAC_PLUS_AUTHEN_STATUS_GETPASS) {

            //--- CONT ---------------------------------------------------------
            $in = null;


            $cont = new AuthCont();
            $bin_cont = $cont->toBinary();

            $hdr = new PacketHeader();
            $hdr->setVersion(TAC_PLUS_VER_ONE);
            $hdr->setSequenceNumber(($this->lastSeqNo + 1));
            $hdr->setSessionId($sessionId);
            $hdr->setData($bin_start);

            $bin_hdr = $hdr->toBinary();
            $pad = $hdr->getPseudoPad($this->secret);
            $in = $bin_hdr . ( $bin_cont ^ $pad );

            $this->send($in);

            //--- REPLY --------------------------------------------------------
            $out = $this->recv();

            $builder = $this->getReplyPacketBuilder();
            $reply = $builder->build();
            $reply->parseBinary($out);
        }

        $this->disconnect();
    }

    /**
     * Get Start packet builder
     *
     * @return StartPacketBuilder
     */
    protected function getStartPacketBuilder()
    {
        return new \TACACS\Authentication\StartPacketBuilder();
    }

    /**
     * Get Reply packet builder
     *
     * @return ReplyPacketBuilder
     */
    protected function getReplyPacketBuilder()
    {
        return new \TACACS\Authentication\ReplyPacketBuilder();
    }

    /**
     * Connect
     *
     * @return boolean
     */
    protected function connect()
    {
        $this->socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        if ($this->socket === false) {
            $this->log(
                "socket_create() failed: reason: " .
                socket_strerror(socket_last_error()) . ""
            );
            return false;
        }

        $result = @socket_connect($this->socket, $this->addr, $this->port);
        if ($result === false) {
            $this->log(
                "socket_connect() failed: reason: ($result) " .
                socket_strerror(socket_last_error($this->socket)) . ""
            );
            return false;
        }

        return true;
    }

    /**
     * Disconnect
     *
     * @return void
     */
    protected function disconnect()
    {
        @socket_close($this->socket);
        $this->log("Disconnected!");
    }

    /**
     * Send
     *
     * @param string $data The data
     *
     * @return void
     */
    protected function send($data)
    {
        $this->log("Sending TACACS+ message... ");
        socket_write($this->socket, $data, strlen($data));
        $this->log("SENT: ". print_r(unpack("H*", $data)[1], true) ."");
    }

    /**
     * Recv
     *
     * @return string
     */
    protected function recv()
    {
        $this->log("Reading TACACS+ response... ");
        $out = null;
        $bytes = 0;
        if (false !== ($bytes = socket_recv(
            $this->socket, $out,
            2048, MSG_WAITALL
        ))) {
            $this->log("DONE (read $bytes bytes)!");
        } else {
            $this->log("ERROR READING SOCKET!");
        }
        $this->log("RECV: ". print_r(unpack("H*", $out)[1], true) ."");
        return $out;
    }

    /**
     * Generates a session id
     *
     * @return string
     */
    protected function genSessionId()
    {
        mt_srand();
        return mt_rand(1, (pow(2, 16)-1));
    }

    /**
     * Log
     *
     * @param mixed $obj The record to log
     *
     * @return void
     */
    protected function log($obj = "")
    {
        if ($this->logger) {
            $this->logger->debug($obj);
        }
    }

    /**
     * Set logger
     *
     * @param LoggerInterface $logger The logger
     *
     * @return void
     */
    public function setLogger(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }
}