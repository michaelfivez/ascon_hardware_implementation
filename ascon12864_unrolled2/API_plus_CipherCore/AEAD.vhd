-------------------------------------------------------------------------------
--! @file       AEAD.vhd
--! @brief      Top-level of authenticated encryption unit containing logic and memory region.
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
use work.AEAD_pkg.all;
entity AEAD is
    generic (
        G_PWIDTH             : integer := 32;
        G_SWIDTH             : integer := 32;
        G_AUX_FIFO_CAPACITY  : integer := 131072
    );
    port (
        --! Global signals
        clk                  : in  std_logic;
        rst                  : in  std_logic;

        --! Data in signals
        pdi                  : in  std_logic_vector(G_PWIDTH            -1 downto 0);
        pdi_valid            : in  std_logic;
        pdi_ready            : out std_logic;

        --! Key signals
        sdi                  : in  std_logic_vector(G_SWIDTH            -1 downto 0);
        sdi_valid            : in  std_logic;
        sdi_ready            : out std_logic;

        --! Data out signals
        do                   : out std_logic_vector(G_PWIDTH            -1 downto 0);
        do_ready             : in  std_logic;
        do_valid             : out std_logic
    );
end AEAD;

-------------------------------------------------------------------------------
--! @brief  Architecture definition of crypto_template
-------------------------------------------------------------------------------
architecture structure of AEAD is
    constant AUX_FIFO_DEPTH         : integer := G_AUX_FIFO_CAPACITY/G_PWIDTH;
    signal   bypass_fifo_rd         : std_logic;
    signal   bypass_fifo_wr         : std_logic;
    signal   bypass_fifo_data       : std_logic_vector(G_PWIDTH-1 downto 0);
    signal   bypass_fifo_full       : std_logic;
    signal   bypass_fifo_empty      : std_logic;
    signal   aux_fifo_din           : std_logic_vector(G_PWIDTH-1 downto 0);
    signal   aux_fifo_dout          : std_logic_vector(G_PWIDTH-1 downto 0);
    signal   aux_fifo_ctrl          : std_logic_vector(3 downto 0);
    signal   aux_fifo_status        : std_logic_vector(2 downto 0);    
begin
    u_logic:
    entity work.AEAD_Core(structure)
    generic map (
        G_W                     => G_PWIDTH ,
        G_SW                    => G_SWIDTH
    )
    port    map (
        clk                     => clk      ,
        rst                     => rst      ,
        pdi                     => pdi      ,
        pdi_valid               => pdi_valid,
        pdi_ready               => pdi_ready,
        sdi                     => sdi      ,
        sdi_valid               => sdi_valid,
        sdi_ready               => sdi_ready,
        do                      => do       ,
        do_ready                => do_ready ,
        do_valid                => do_valid ,

        --! FIFO signals
        bypass_fifo_wr          => bypass_fifo_wr,
        bypass_fifo_rd          => bypass_fifo_rd,
        bypass_fifo_data        => bypass_fifo_data,
        bypass_fifo_full        => bypass_fifo_full,
        bypass_fifo_empty       => bypass_fifo_empty,
        aux_fifo_din            => aux_fifo_din,
        aux_fifo_dout           => aux_fifo_dout,
        aux_fifo_ctrl           => aux_fifo_ctrl,
        aux_fifo_status         => aux_fifo_status
    );

    u_memory: block
    begin
        u_bypass_fifo:
        entity work.fifo(structure)
        generic map (G_W => G_PWIDTH, G_LOG2DEPTH => 6)
        port map    (
            clk                 => clk              ,
            rst                 => rst              ,
            write               => bypass_fifo_wr   ,
            read                => bypass_fifo_rd   ,
            din                 => pdi              ,
            dout                => bypass_fifo_data ,
            almost_full         => bypass_fifo_full ,
            empty               => bypass_fifo_empty
        );

        u_aux_fifo:
        entity work.aux_fifo(structure)
        generic map (G_W => G_PWIDTH, G_LOG2DEPTH => log2_ceil(AUX_FIFO_DEPTH))
        port map    (
            clk                 => clk           ,
            rst                 => rst           ,
            fifo_din            => aux_fifo_din  ,
            fifo_dout           => aux_fifo_dout ,
            fifo_ctrl_in        => aux_fifo_ctrl ,
            fifo_ctrl_out       => aux_fifo_status
        );
    end block u_memory;
end structure;