-------------------------------------------------------------------------------
--! @file       PreProcessor.vhd
--! @brief      Pre-processing unit for an authenticated encryption module.
--! @project    CAESAR Candidate Evaluation
--! @author     Ekawat (ice) Homsirikamol
--! @copyright  Copyright (c) 2015 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             —unrestricted)
--!
--! SIPO used within this unit follows the following convention:
--! > Order in the test vector file (left to right):  A(0) A(1) A(2) … A(N-1)
--! > Order at the SIPO input (time 0 to time N-1) :  A(0) A(1) A(2) … A(N-1)
--! > Order at the SIPO output (left to right)     :  A(0) A(1) A(2) … A(N-1)
--! where A is a single I/O word.
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use work.AEAD_pkg.all;

entity PreProcessor is
    generic (
        G_W                 : integer := 32;   --! Public data width (bits)
        G_SW                : integer := 32;   --! Secret data width (bits)
        G_NPUB_SIZE         : integer := 128;  --! Npub width (bits)
        G_NSEC_ENABLE       : integer := 0;    --! Enable NSEC port
        G_NSEC_SIZE         : integer := 128;  --! Nsec width (bits)
        G_ABLK_SIZE         : integer := 128;  --! Authenticated Data Block size (bits)
        G_DBLK_SIZE         : integer := 128;  --! Data Block size (bits)
        G_KEY_SIZE          : integer := 128;  --! Key size (bits)
        G_RDKEY_ENABLE      : integer := 0;    --! Enable rdkey port (also disables key port)
        G_RDKEY_SIZE        : integer := 128;  --! Roundkey size (bits)
        G_TAG_SIZE          : integer := 128;  --! Tag size (bits)
        G_BS_BYTES          : integer := 4;    --! The number of bits required to hold block size expressed in bytes = log2_ceil(max(G_ABLK_SIZE,G_DBLK_SIZE)/8)
        G_LOADLEN_ENABLE    : integer := 0;    --! Enable load length section
        G_PAD               : integer := 1;    --! Enable padding
        G_PAD_STYLE         : integer := 1;    --! Padding style
        G_PAD_AD            : integer := 1;    --! (G_PAD's sub option) Enable AD Padding
        G_PAD_D             : integer := 1;    --! (G_PAD's sub option) Enable Data padding
        G_CTR_AD_SIZE       : integer := 16;   --! Maximum size for the counter that keeps track of authenticated data
        G_CTR_D_SIZE        : integer := 16;   --! Maximum size for the counter that keeps track of data
        G_PLAINTEXT_MODE    : integer := 0;    --! Plaintext Mode
        G_CIPHERTEXT_MODE   : integer := 0;    --! Ciphertext mode
        G_REVERSE_DBLK      : integer := 0     --! Reverse block order (for message only)
    );
    port (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk                 : in  std_logic;
        rst                 : in  std_logic;

        --! Data in signals
        pdi                 : in  std_logic_vector(G_W                        -1 downto 0);
        pdi_valid           : in  std_logic;
        pdi_ready           : out std_logic;

        --! Key signals
        sdi                 : in  std_logic_vector(G_SW                       -1 downto 0);
        sdi_valid           : in  std_logic;
        sdi_ready           : out std_logic;

        --! =================
        --! Crypto Core Signals
        --! =================
        --! Data signals
        key                 : out std_logic_vector(G_KEY_SIZE                 -1 downto 0);       --! Key data
        rdkey               : out std_logic_vector(G_RDKEY_SIZE               -1 downto 0);       --! Round key data
        bdi                 : out std_logic_vector(G_DBLK_SIZE                -1 downto 0);       --! Block data
        npub                : out std_logic_vector(G_NPUB_SIZE                -1 downto 0);       --! Npub data
        nsec                : out std_logic_vector(G_NSEC_SIZE                -1 downto 0);       --! Nsec data
        exp_tag             : out std_logic_vector(G_TAG_SIZE                 -1 downto 0);       --! Tag data
        --! Info signals
        len_a               : out std_logic_vector(G_CTR_AD_SIZE              -1 downto 0);       --! Len of authenticated data in bytes (used for some algorithm)
        len_d               : out std_logic_vector(G_CTR_D_SIZE               -1 downto 0);       --! Len of data in bytes (used for some algorithm)

        --! Control signals
        key_ready           : out std_logic;                                                      --! Indicates that the key is ready
        key_needs_update    : out std_logic;                                                      --! Indicates that the key needs update and should be acknowledge by the core via key_updated signal
        key_updated         : in  std_logic;                                                      --! Key has been updated
        rdkey_ready         : out std_logic;                                                      --! (Optional) Round key ready
        rdkey_read          : in  std_logic := '0';                                               --! (Optional) Round key read
        npub_ready          : out std_logic;                                                      --! (Optional) Npub ready
        npub_read           : in  std_logic;                                                      --! (Optional) Npub read
        nsec_ready          : out std_logic;                                                      --! (Optional) Nsec ready
        nsec_read           : in  std_logic := '0';                                               --! (Optional) Nsec read
        bdi_ready           : out std_logic;                                                      --! Block ready
        bdi_proc            : out std_logic;                                                      --! Block processing
        bdi_ad              : out std_logic;                                                      --! Input block is an authenticated data
        bdi_nsec            : out std_logic;                                                      --! Input block is a secret message number
        bdi_decrypt         : out std_logic;                                                      --! Decryption operation
        bdi_pad             : out std_logic;                                                      --! Last block of segment type contain padding
        bdi_eot             : out std_logic;                                                      --! Last block of segment type (end-of-type)
        bdi_eoi             : out std_logic;                                                      --! Last block of message (end-of-message)
        bdi_nodata          : out std_logic;                                                      --! Control signal indicating that there's no plain-text or authenticated data. The unit should generate a tag right away.
        bdi_read            : in  std_logic;                                                      --! Handshake signal indicating that the data block has been read
        bdi_size            : out std_logic_vector(G_BS_BYTES                 -1 downto 0);       --! Block size signal. Note: 0 = Full block.
        bdi_valid_bytes     : out std_logic_vector(G_DBLK_SIZE/8              -1 downto 0);       --! Valid bytes
        bdi_pad_loc         : out std_logic_vector(G_DBLK_SIZE/8              -1 downto 0);       --! PAD location
        exp_tag_ready       : out std_logic;                                                      --! Expected tag is ready
        msg_auth_done       : in  std_logic;                                                      --! Message authentication completion signal

        --! FIFO
        bypass_fifo_full    : in  std_logic;                                                      --! An input signal indicating that the bypass FIFO is full
        bypass_fifo_wr      : out std_logic                                                       --! An output signal for writing data to bypass FIFO
    );
end PreProcessor;

architecture structure of PreProcessor is
    function isNPUBdisabled (a : integer ) return integer is
    begin
        if (a = 1 or a = 2) then
            return 1;
        else
            return 0;
        end if;
    end function isNPUBdisabled;
    function isKeyak (blksize: integer) return integer is
    begin
        if (G_DBLK_SIZE = 1344) then
            return 1;
        else
            return 0;
        end if;
    end function isKeyak;

    constant NPUB_DISABLE       : integer := isNPUBdisabled(G_PLAINTEXT_MODE);
    constant IS_KEYAK           : integer := isKeyak(G_DBLK_SIZE);
    signal en_data              : std_logic;
    signal en_npub              : std_logic;
    signal en_nsec              : std_logic;
    signal en_key               : std_logic;
    signal en_rdkey             : std_logic;
    signal sel_blank_pdi        : std_logic;
    signal clr_len              : std_logic;
    signal en_len_a_r           : std_logic;
    signal en_len_d_r           : std_logic;
    signal en_len_last_r        : std_logic;
    signal en_len_a             : std_logic;
    signal en_len_d             : std_logic;
    signal pad_enable           : std_logic;
    signal en_pad_loc           : std_logic;
    signal pad_eot              : std_logic;
    signal pad_eoi              : std_logic;
    signal pad_type_ad          : std_logic;
    signal pad_shift            : std_logic_vector(log2_ceil(G_W/8)           -1 downto 0);
    signal size_dword           : std_logic_vector(log2_ceil(G_W/8)              downto 0);
    signal en_exp_tag           : std_logic;
    signal sel_input            : std_logic_vector(2 downto 0);
    signal en_last_word         : std_logic;
    signal key_updated_sel      : std_logic;
    signal key_updated_int      : std_logic;
begin
    uDP: entity work.PreProcessor_Datapath(dataflow)
    generic map (
        G_W                         => G_W                     ,
        G_SW                        => G_SW                    ,
        G_CTR_AD_SIZE               => G_CTR_AD_SIZE           ,
        G_CTR_D_SIZE                => G_CTR_D_SIZE            ,
        G_DBLK_SIZE                 => G_DBLK_SIZE             ,
        G_KEY_SIZE                  => G_KEY_SIZE              ,
        G_KEYAK                     => IS_KEYAK                ,
        G_NPUB_DISABLE              => NPUB_DISABLE            ,
        G_NPUB_SIZE                 => G_NPUB_SIZE             ,
        G_NSEC_ENABLE               => G_NSEC_ENABLE           ,
        G_NSEC_SIZE                 => G_NSEC_SIZE             ,
        G_LOADLEN_ENABLE            => G_LOADLEN_ENABLE        ,
        G_PAD                       => G_PAD                   ,
        G_PAD_STYLE                 => G_PAD_STYLE             ,
        G_RDKEY_ENABLE              => G_RDKEY_ENABLE          ,
        G_RDKEY_SIZE                => G_RDKEY_SIZE            ,
        G_TAG_SIZE                  => G_TAG_SIZE
    )
    port map (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk                         => clk                     ,
        rst                         => rst                     ,
        pdi                         => pdi                     ,
        sdi                         => sdi                     ,

        --! =================
        --! Crypto Core Signals
        --! =================
        key_updated                 => key_updated_sel         ,
        key                         => key                     ,
        rdkey                       => rdkey                   ,
        bdi                         => bdi                     ,
        npub                        => npub                    ,
        nsec                        => nsec                    ,
        len_a                       => len_a                   ,
        len_d                       => len_d                   ,
        exp_tag                     => exp_tag                 ,
        bdi_valid_bytes             => bdi_valid_bytes         ,
        bdi_pad_loc                 => bdi_pad_loc             ,

        --! =================
        --! Internal Signals
        --! =================
        pad_shift                   => pad_shift               ,
        en_data                     => en_data                 ,
        en_npub                     => en_npub                 ,
        en_nsec                     => en_nsec                 ,
        en_key                      => en_key                  ,
        en_rdkey                    => en_rdkey                ,
        sel_blank_pdi               => sel_blank_pdi           ,
        clr_len                     => clr_len                 ,
        en_len_a_r                  => en_len_a_r              ,
        en_len_d_r                  => en_len_d_r              ,
        en_len_last_r               => en_len_last_r           ,
        en_len_a                    => en_len_a                ,
        en_len_d                    => en_len_d                ,        
        en_exp_tag                  => en_exp_tag              ,
        size_dword                  => size_dword              ,
        en_last_word                => en_last_word            ,
        --! Pad related control
        pad_eot                     => pad_eot                 ,
        pad_eoi                     => pad_eoi                 ,
        pad_type_ad                 => pad_type_ad             ,
        pad_enable                  => pad_enable              ,
        en_pad_loc                  => en_pad_loc              ,
        --! Supplmental control
        sel_input                   => sel_input
    );


    uCtrl: entity work.PreProcessor_Control(behavior)
    generic map (
        G_W                         => G_W                  ,
        G_SW                        => G_SW                 ,
        G_CIPHERTEXT_MODE           => G_CIPHERTEXT_MODE    ,
        G_PLAINTEXT_MODE            => G_PLAINTEXT_MODE     ,
        G_ABLK_SIZE                 => G_ABLK_SIZE          ,
        G_DBLK_SIZE                 => G_DBLK_SIZE          ,
        G_BS_BYTES                  => G_BS_BYTES           ,
        G_KEY_SIZE                  => G_KEY_SIZE           ,
        G_NPUB_DISABLE              => NPUB_DISABLE         ,
        G_NPUB_SIZE                 => G_NPUB_SIZE          ,
        G_NSEC_ENABLE               => G_NSEC_ENABLE        ,
        G_NSEC_SIZE                 => G_NSEC_SIZE          ,
        G_RDKEY_ENABLE              => G_RDKEY_ENABLE       ,
        G_RDKEY_SIZE                => G_RDKEY_SIZE         ,
        G_REVERSE_DBLK              => G_REVERSE_DBLK       ,
        G_LOADLEN_ENABLE            => G_LOADLEN_ENABLE     ,
        G_CTR_AD_SIZE               => G_CTR_AD_SIZE        ,
        G_CTR_D_SIZE                => G_CTR_D_SIZE         ,
        G_PAD                       => G_PAD                ,
        G_PAD_AD                    => G_PAD_AD             ,
        G_PAD_D                     => G_PAD_D              ,
        G_TAG_SIZE                  => G_TAG_SIZE           ,
        G_KEYAK                     => IS_KEYAK
    )
    port map (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk                         => clk                  ,
        rst                         => rst                  ,
        pdi                         => pdi                  ,
        pdi_valid                   => pdi_valid            ,
        pdi_ready                   => pdi_ready            ,
        sdi                         => sdi                  ,
        sdi_valid                   => sdi_valid            ,
        sdi_ready                   => sdi_ready            ,
        error                       => open                 ,

        --! =================
        --! Crypto Core Signals
        --! =================
        --! control signals
        key_ready                   => key_ready            ,
        key_needs_update            => key_needs_update     ,
        key_updated                 => key_updated_sel      ,
        rdkey_ready                 => rdkey_ready          ,
        rdkey_read                  => rdkey_read           ,
        npub_ready                  => npub_ready           ,
        npub_read                   => npub_read            ,
        nsec_read                   => nsec_read            ,
        nsec_ready                  => nsec_ready           ,
        bdi_ready                   => bdi_ready            ,
        bdi_proc                    => bdi_proc             ,
        bdi_ad                      => bdi_ad               ,
        bdi_nsec                    => bdi_nsec             ,
        bdi_decrypt                 => bdi_decrypt          ,
        bdi_pad                     => bdi_pad              ,
        bdi_eot                     => bdi_eot              ,
        bdi_eoi                     => bdi_eoi              ,
        bdi_nodata                  => bdi_nodata           ,
        bdi_read                    => bdi_read             ,
        bdi_size                    => bdi_size             ,
        bypass_fifo_full            => bypass_fifo_full     ,
        bypass_fifo_wr              => bypass_fifo_wr       ,
        exp_tag_ready               => exp_tag_ready        ,
        msg_auth_done               => msg_auth_done        ,

        --! =================
        --! Internal Signals
        --! =================
        pad_shift                   => pad_shift            ,
        en_data                     => en_data              ,
        en_npub                     => en_npub              ,
        en_nsec                     => en_nsec              ,
        en_key                      => en_key               ,
        en_rdkey                    => en_rdkey             ,
        sel_blank_pdi               => sel_blank_pdi        ,
        clr_len                     => clr_len              ,
        en_len_a_r                  => en_len_a_r           ,
        en_len_d_r                  => en_len_d_r           ,
        en_len_last_r               => en_len_last_r        ,
        en_len_a                    => en_len_a             ,
        en_len_d                    => en_len_d             ,
        en_exp_tag                  => en_exp_tag           ,
        size_dword                  => size_dword           ,
        en_last_word                => en_last_word         ,
        --! Pad related control
        pad_eot                     => pad_eot              ,
        pad_eoi                     => pad_eoi              ,
        pad_type_ad                 => pad_type_ad          ,
        pad_enable                  => pad_enable           ,
        en_pad_loc                  => en_pad_loc           ,
        --! Supplmental control
        key_updated_int             => key_updated_int      ,   --! Only used for Keyak
        sel_input                   => sel_input
    );

    gKeyak1: if (IS_KEYAK = 1) generate
        key_updated_sel <= key_updated_int;
    end generate;
    gKeyak0: if (IS_KEYAK = 0) generate
        key_updated_sel <= key_updated;
    end generate;
end structure;
