-------------------------------------------------------------------------------
--! @file       AEAD_Core.vhd
--! @brief      Authenticated encryption unit core template module.
--!             User should modification to the default generics based on the
--!             implemented cipher.
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
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;

entity AEAD_Core is
    generic (
        G_W                      : integer := 32;   --! Public data width (bits)
        G_SW                     : integer := 32;   --! Secret data width (bits)
        G_NPUB_SIZE              : integer := 128;  --! IV or Nonce size (bits)
        G_NSEC_ENABLE            : integer := 0;    --! Enable NSEC port
        G_NSEC_SIZE              : integer := 1;    --! NSEC width (bits)        
        G_ABLK_SIZE              : integer := 128;  --! Authenticated Data Block size (bits)
        G_DBLK_SIZE              : integer := 128;  --! Data Block size (bits)
        G_KEY_SIZE               : integer := 128;  --! Key size (bits)
        G_RDKEY_ENABLE           : integer := 0;    --! Enable rdkey port (also disables key port)
        G_RDKEY_SIZE             : integer := 1;    --! Roundkey size (bits)        
        G_TAG_SIZE               : integer := 128;  --! Tag size (bits)
        G_BS_BYTES               : integer := 4;    --! The number of bits required to hold block size expressed in bytes = log2_ceil(max(G_ABLK_SIZE,G_DBLK_SIZE)/8)
        G_LOADLEN_ENABLE         : integer := 0;    --! Enable load length section
        G_PAD                    : integer := 1;    --! Enable padding
        G_PAD_STYLE              : integer := 1;    --! Padding mode
        G_PAD_AD                 : integer := 1;    --! (G_PAD's sub option) Enable AD Padding
        G_PAD_D                  : integer := 1;    --! (G_PAD's sub option) Enable Data padding
        G_CTR_AD_SIZE            : integer := 16;   --! Maximum AD len value
        G_CTR_D_SIZE             : integer := 16;   --! Maximum data len value
        G_PLAINTEXT_MODE         : integer := 0;    --! Plaintext Mode
        G_CIPHERTEXT_MODE        : integer := 0;    --! Ciphertext mode
        G_REVERSE_DBLK           : integer := 0     --! Reverse block order (for message only)
    );
    port (
        --! Global signals
        clk                     :   in  std_logic;
        rst                     :   in  std_logic;

        --! Data in signals
        pdi                     :   in  std_logic_vector(G_W            -1 downto 0);
        pdi_valid               :   in  std_logic;
        pdi_ready               :   out std_logic;

        --! Key signals
        sdi                     :   in  std_logic_vector(G_SW           -1 downto 0);
        sdi_valid               :   in  std_logic;
        sdi_ready               :   out std_logic;

        --! Data out signals
        do                      :   out std_logic_vector(G_W            -1 downto 0);
        do_ready                :   in  std_logic;
        do_valid                :   out std_logic;

        --! FIFO signals
        bypass_fifo_wr          :   out std_logic;
        bypass_fifo_rd          :   out std_logic;
        bypass_fifo_full        :   in  std_logic;
        bypass_fifo_empty       :   in  std_logic;
        bypass_fifo_data        :   in  std_logic_vector(G_W            -1 downto 0);
        aux_fifo_din            :   out std_logic_vector(G_W            -1 downto 0);
        aux_fifo_ctrl           :   out std_logic_vector(4              -1 downto 0);
        aux_fifo_dout           :   in  std_logic_vector(G_W            -1 downto 0);
        aux_fifo_status         :   in  std_logic_vector(3              -1 downto 0)
    );
end AEAD_Core;

-------------------------------------------------------------------------------
--! @brief  Architecture definition of AEAD_Core
-------------------------------------------------------------------------------
architecture structure of AEAD_Core is
    --! Signals from input processor
    signal npub                 : std_logic_vector(G_NPUB_SIZE             -1 downto 0);
    signal nsec                 : std_logic_vector(G_NSEC_SIZE             -1 downto 0);
    signal key                  : std_logic_vector(G_KEY_SIZE              -1 downto 0);
    signal rdkey                : std_logic_vector(G_RDKEY_SIZE            -1 downto 0);
    signal bdi                  : std_logic_vector(G_DBLK_SIZE             -1 downto 0);
    signal exp_tag              : std_logic_vector(G_TAG_SIZE              -1 downto 0);
    signal len_a                : std_logic_vector(G_CTR_AD_SIZE           -1 downto 0);
    signal len_d                : std_logic_vector(G_CTR_D_SIZE            -1 downto 0);

    signal key_ready            : std_logic;
    signal key_updated          : std_logic;
    signal key_needs_update     : std_logic;
    signal rdkey_ready          : std_logic;
    signal rdkey_read           : std_logic;    
    signal npub_ready           : std_logic;
    signal npub_read            : std_logic;    
    signal nsec_ready           : std_logic;
    signal nsec_read            : std_logic;
    signal bdi_ready            : std_logic;
    signal bdi_proc             : std_logic;
    signal bdi_ad               : std_logic;
    signal bdi_nsec             : std_logic;
    signal bdi_pad              : std_logic;
    signal bdi_decrypt          : std_logic;
    signal bdi_eot              : std_logic;
    signal bdi_eoi              : std_logic;
    signal bdi_read             : std_logic;
    signal bdi_size             : std_logic_vector(G_BS_BYTES              -1 downto 0);
    signal bdi_valid_bytes      : std_logic_vector(G_DBLK_SIZE/8           -1 downto 0);
    signal bdi_pad_loc          : std_logic_vector(G_DBLK_SIZE/8           -1 downto 0);
    signal bdi_nodata           : std_logic;
    signal exp_tag_ready        : std_logic;

    --! Signals to output processor
    signal bdo_ready            : std_logic;
    signal bdo_write            : std_logic;
    signal bdo                  : std_logic_vector(G_DBLK_SIZE             -1 downto 0);
    signal bdo_size             : std_logic_vector(G_BS_BYTES+1            -1 downto 0);
    signal bdo_nsec             : std_logic;
    signal tag_ready            : std_logic;
    signal tag_write            : std_logic;
    signal tag                  : std_logic_vector(G_TAG_SIZE              -1 downto 0);
    signal msg_auth_done        : std_logic;
    signal msg_auth_valid       : std_logic;
begin
    u_input:
    entity work.PreProcessor(structure)
    generic map (
        G_W                 => G_W              ,
        G_SW                => G_SW             ,
        G_NPUB_SIZE         => G_NPUB_SIZE      ,
        G_NSEC_ENABLE       => G_NSEC_ENABLE    ,
        G_NSEC_SIZE         => G_NSEC_SIZE      ,
        G_ABLK_SIZE         => G_ABLK_SIZE      ,
        G_DBLK_SIZE         => G_DBLK_SIZE      ,
        G_KEY_SIZE          => G_KEY_SIZE       ,
        G_RDKEY_ENABLE      => G_RDKEY_ENABLE   ,
        G_RDKEY_SIZE        => G_RDKEY_SIZE     ,
        G_TAG_SIZE          => G_TAG_SIZE       ,
        G_BS_BYTES          => G_BS_BYTES       ,
        G_LOADLEN_ENABLE    => G_LOADLEN_ENABLE ,
        G_PAD               => G_PAD            ,
        G_PAD_STYLE         => G_PAD_STYLE      ,
        G_PAD_AD            => G_PAD_AD         ,
        G_PAD_D             => G_PAD_D          ,
        G_CTR_AD_SIZE       => G_CTR_AD_SIZE    ,
        G_CTR_D_SIZE        => G_CTR_D_SIZE     ,
        G_PLAINTEXT_MODE    => G_PLAINTEXT_MODE ,
        G_CIPHERTEXT_MODE   => G_CIPHERTEXT_MODE,
        G_REVERSE_DBLK      => G_REVERSE_DBLK
    )
    port map (
        clk                 => clk              ,
        rst                 => rst              ,

        --! External
        pdi                 => pdi              ,
        pdi_valid           => pdi_valid        ,
        pdi_ready           => pdi_ready        ,
        sdi                 => sdi              ,
        sdi_valid           => sdi_valid        ,
        sdi_ready           => sdi_ready        ,
        --! Datapath
        npub                => npub             ,
        nsec                => nsec             ,
        key                 => key              ,
        rdkey               => rdkey            ,
        bdi                 => bdi              ,        
        exp_tag             => exp_tag          ,
        len_a               => len_a            ,
        len_d               => len_d            ,

        --! Controller
        key_ready           => key_ready        ,
        key_updated         => key_updated      ,
        key_needs_update    => key_needs_update ,
        rdkey_ready         => rdkey_ready      ,
        rdkey_read          => rdkey_read       ,
        npub_ready          => npub_ready       ,
        npub_read           => npub_read        ,        
        nsec_ready          => nsec_ready       ,
        nsec_read           => nsec_read        ,
        bdi_ready           => bdi_ready        ,
        bdi_proc            => bdi_proc         ,
        bdi_ad              => bdi_ad           ,
        bdi_nsec            => bdi_nsec         ,
        bdi_pad             => bdi_pad          ,
        bdi_decrypt         => bdi_decrypt      ,
        bdi_eot             => bdi_eot          ,
        bdi_eoi             => bdi_eoi          ,
        bdi_nodata          => bdi_nodata       ,
        bdi_read            => bdi_read         ,
        bdi_size            => bdi_size         ,
        bdi_valid_bytes     => bdi_valid_bytes  ,
        bdi_pad_loc         => bdi_pad_loc      ,
        exp_tag_ready       => exp_tag_ready    ,
        msg_auth_done       => msg_auth_done    ,

        --! FIFO
        bypass_fifo_wr      => bypass_fifo_wr   ,
        bypass_fifo_full    => bypass_fifo_full
    );

    u_cc:
    entity work.CipherCore(structure)
    generic map (
        G_NPUB_SIZE         => G_NPUB_SIZE      ,
        G_NSEC_SIZE         => G_NSEC_SIZE      ,    
        G_DBLK_SIZE         => G_DBLK_SIZE      ,
        G_KEY_SIZE          => G_KEY_SIZE       ,
        G_RDKEY_SIZE        => G_RDKEY_SIZE     ,
        G_TAG_SIZE          => G_TAG_SIZE       ,
        G_BS_BYTES          => G_BS_BYTES       ,
        G_CTR_AD_SIZE       => G_CTR_AD_SIZE    ,
        G_CTR_D_SIZE        => G_CTR_D_SIZE
    )
    port map (
        clk                 => clk              ,
        rst                 => rst              ,
        
        npub                => npub             ,
        nsec                => nsec             ,
        key                 => key              ,
        rdkey               => rdkey            ,
        bdi                 => bdi              ,        
        exp_tag             => exp_tag          ,
        len_a               => len_a            ,
        len_d               => len_d            ,

        key_ready           => key_ready        ,
        key_updated         => key_updated      ,
        key_needs_update    => key_needs_update ,
        rdkey_ready         => rdkey_ready      ,
        rdkey_read          => rdkey_read       ,
        npub_ready          => npub_ready       ,
        npub_read           => npub_read        ,        
        nsec_ready          => nsec_ready       ,
        nsec_read           => nsec_read        ,
        bdi_ready           => bdi_ready        ,
        bdi_proc            => bdi_proc         ,
        bdi_ad              => bdi_ad           ,
        bdi_nsec            => bdi_nsec         ,
        bdi_pad             => bdi_pad          ,
        bdi_decrypt         => bdi_decrypt      ,
        bdi_eot             => bdi_eot          ,
        bdi_eoi             => bdi_eoi          ,
        bdi_read            => bdi_read         ,
        bdi_size            => bdi_size         ,
        bdi_valid_bytes     => bdi_valid_bytes  ,
        bdi_pad_loc         => bdi_pad_loc      ,
        bdi_nodata          => bdi_nodata       ,
        exp_tag_ready       => exp_tag_ready    ,
        msg_auth_done       => msg_auth_done    ,

        bdo_write           => bdo_write        ,
        bdo_ready           => bdo_ready        ,
        bdo                 => bdo              ,
        bdo_size            => bdo_size         ,
        bdo_nsec            => bdo_nsec         ,
        tag_write           => tag_write        ,
        tag_ready           => tag_ready        ,
        tag                 => tag              ,
        msg_auth_valid      => msg_auth_valid
    );


    u_output:
    entity work.PostProcessor(structure)
    generic map (
        G_W                 => G_W              ,
        G_DBLK_SIZE         => G_DBLK_SIZE      ,
        G_BS_BYTES          => G_BS_BYTES       ,
        G_TAG_SIZE          => G_TAG_SIZE       ,
        G_NSEC_ENABLE       => G_NSEC_ENABLE    ,
        G_LOADLEN_ENABLE    => G_LOADLEN_ENABLE ,
        G_CIPHERTEXT_MODE   => G_CIPHERTEXT_MODE,
        G_REVERSE_DBLK      => G_REVERSE_DBLK   ,
        G_PAD               => G_PAD            ,
        G_PAD_D             => G_PAD_D
    )
    port map    (
        --! Global
        clk                 => clk              ,
        rst                 => rst              ,

        --! External
        do                  => do               ,
        do_ready            => do_ready         ,
        do_valid            => do_valid         ,

        --! Processor
        bdo_ready           => bdo_ready        ,
        bdo_write           => bdo_write        ,
        bdo_data            => bdo              ,
        bdo_size            => bdo_size         ,
        bdo_nsec            => bdo_nsec         ,
        tag_ready           => tag_ready        ,
        tag_write           => tag_write        ,
        tag_data            => tag              ,
        msg_auth_done       => msg_auth_done    ,
        msg_auth_valid      => msg_auth_valid   ,

        --! FIFOs
        bypass_fifo_empty   => bypass_fifo_empty,
        bypass_fifo_rd      => bypass_fifo_rd   ,
        bypass_fifo_data    => bypass_fifo_data ,
        aux_fifo_din        => aux_fifo_din     ,
        aux_fifo_ctrl       => aux_fifo_ctrl    ,
        aux_fifo_dout       => aux_fifo_dout    ,
        aux_fifo_status     => aux_fifo_status
    );
end structure;