-------------------------------------------------------------------------------
--! @file       PostProcessor.vhd
--! @brief      Post=processing unit for an authenticated encryption module.
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
--! PISO used within this unit follows the following convention:
--! > Order at the PISO input (left to right)      :  A(0) A(1) A(2) … A(N-1)
--! > Order at the PISO output (time 0 to time N-1):  A(0) A(1) A(2) … A(N-1)
--! > Order in the test vector file (left to right):  A(0) A(1) A(2) … A(N-1)
--! where A is a single I/O word.
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use work.AEAD_pkg.all;

entity PostProcessor is
    generic (
        G_W                     : integer := 64;      --! Output width (bits)
        G_DBLK_SIZE             : integer := 128;     --! Block size (bits)
        G_BS_BYTES              : integer := 4;       --! The number of bits required to hold block size expressed in bytes = log2_ceil(block_size/8)
        G_TAG_SIZE              : integer := 128;     --! Tag size (bits)
        G_CIPHERTEXT_MODE       : integer := 0;       --! Ciphertext processing mode
        G_REVERSE_DBLK          : integer := 0;       --! Reverse datablock
        G_NSEC_ENABLE           : integer := 0;       --! Enable NSEC port
        G_LOADLEN_ENABLE        : integer := 0;       --! Enable load length section
        G_PAD                   : integer := 1;       --! Enable padding
        G_PAD_D                 : integer := 0        --! Padding mode (used if G_PAD_D = 2 [extra data block])
    );
    port (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk                 :   in  std_logic;
        rst                 :   in  std_logic;

        --! Data out signals
        do                  :   out std_logic_vector(G_W                               -1 downto 0);   --! Output FIFO data
        do_ready            :   in  std_logic;                                                         --! Output FIFO ready
        do_valid            :   out std_logic;                                                         --! Output FIFO write


        --! =================
        --! Internal Signals
        --! =================
        --! Datapath signal
        bdo_ready          :   out std_logic;                                                          --! Output PISO ready (Let crypto core knows that it's ready to accept data)
        bdo_write          :   in  std_logic;                                                          --! Write to output PISO
        bdo_data           :   in  std_logic_vector(G_DBLK_SIZE                       -1 downto 0);    --! BDO data
        bdo_size           :   in  std_logic_vector(G_BS_BYTES+1                      -1 downto 0);    --! BDO size (only active when G_CIPHERTEXT_MODE = 2 [Cexp_T])
        bdo_nsec           :   in  std_logic;                                                          --! BDO nsec type flag
        tag_ready          :   out std_logic;                                                          --! Output tag ready (Let crypto core knows that it's ready to accept data)
        tag_write          :   in  std_logic;                                                          --! Write to output tag register
        tag_data           :   in  std_logic_vector(G_TAG_SIZE                         -1 downto 0);   --! Tag data
        msg_auth_done      :   in  std_logic;                                                          --! Tag comparison completion signal
        msg_auth_valid     :   in  std_logic;                                                          --! Tag comparison valid signal

        --! FIFO signals
        bypass_fifo_data   :   in  std_logic_vector(G_W                               -1 downto 0);   --! Bypass FIFO data
        bypass_fifo_empty  :   in  std_logic;                                                         --! Bypass FIFO empty
        bypass_fifo_rd     :   out std_logic;                                                         --! Bypass FIFO read
        aux_fifo_din       :   out std_logic_vector(G_W                                -1 downto 0);
        aux_fifo_ctrl      :   out std_logic_vector(3                                     downto 0);
        aux_fifo_dout      :   in  std_logic_vector(G_W                                -1 downto 0);
        aux_fifo_status    :   in  std_logic_vector(2                                     downto 0)
    );
end PostProcessor;

architecture structure of PostProcessor is
    function getPadSetting return integer is
    begin
        if (G_PAD = 1) then
            return G_PAD_D;
        else
            return 0;
        end if;
    end function getPadSetting;
    constant PAD_D              : integer := getPadSetting;

    signal bdo_shf              : std_logic;
    signal sel_instr_actkey     : std_logic;
    signal sel_instr_dec        : std_logic;
    signal sel_hdr              : std_logic;
    signal sel_do               : std_logic_vector(2                                  -1 downto 0);
    signal sel_sw               : std_logic_vector(2                                  -1 downto 0);
    signal sel_sgmt_hdr         : std_logic_vector(2                                  -1 downto 0);
    signal sel_hword            : std_logic;
    signal sel_hword_init       : std_logic;
    signal is_i_type            : std_logic_vector(4                                  -1 downto 0);
    signal is_i_nsec            : std_logic_vector(4                                  -1 downto 0);
    signal msg_id               : std_logic_vector(LEN_MSG_ID                         -1 downto 0);
    signal key_id               : std_logic_vector(LEN_KEY_ID                         -1 downto 0);

    signal en_zeroize           : std_logic;
    signal data_bytes           : std_logic_vector(log2_ceil(G_W/8)                   -1 downto 0);
    signal tag_shf              : std_logic;

    signal save_size            : std_logic;
    signal clr_size             : std_logic;
    signal sel_do2              : std_logic;
    signal sel_do2_eoi          : std_logic;
    signal last_sgmt_size       : std_logic_vector(CTR_SIZE_LIM                 -1 downto 0);
begin
    uDP: entity work.PostProcessor_Datapath(dataflow)
    generic map (
        G_W                => G_W                   ,
        G_BS_BYTES         => G_BS_BYTES            ,
        G_DBLK_SIZE        => G_DBLK_SIZE           ,
        G_TAG_SIZE         => G_TAG_SIZE            ,
        G_CIPHERTEXT_MODE  => G_CIPHERTEXT_MODE     ,
        G_REVERSE_DBLK     => G_REVERSE_DBLK        ,
        G_PAD_D            => PAD_D
    )
    port map (
        --! =================
        --! Global Signals
        --! =================
        clk                => clk                   ,
        rst                => rst                   ,


        --! =================
        --! External signals
        --! =================
        do                 => do                    ,
        bypass_fifo_data   => bypass_fifo_data      ,
        bdo_write          => bdo_write             ,
        bdo_data           => bdo_data              ,
        tag_write          => tag_write             ,
        tag_data           => tag_data              ,
        bdo_size           => bdo_size              ,

        --! =================
        --! Controls
        --! =================
        bdo_shf             => bdo_shf              ,
        tag_shf             => tag_shf              ,
        sel_instr_actkey    => sel_instr_actkey     ,
        sel_instr_dec       => sel_instr_dec        ,

        sel_hdr             => sel_hdr              ,
        sel_do              => sel_do               ,
        sel_sw              => sel_sw               ,
        sel_sgmt_hdr        => sel_sgmt_hdr         ,
        sel_hword           => sel_hword            ,
        sel_hword_init      => sel_hword_init       ,
        is_i_type           => is_i_type            ,
        is_i_nsec           => is_i_nsec            ,
        msg_id              => msg_id               ,
        key_id              => key_id               ,
        data_bytes          => data_bytes           ,

        en_zeroize          => en_zeroize           ,
        save_size           => save_size            ,
        clr_size            => clr_size             ,
        sel_do2             => sel_do2              ,
        sel_do2_eoi         => sel_do2_eoi          ,
        last_sgmt_size      => last_sgmt_size       ,

        --! =================
        --! FIFO
        --! =================
        aux_fifo_din        => aux_fifo_din         ,
        aux_fifo_dout       => aux_fifo_dout
    );

    uCtrl: entity work.PostProcessor_Control(behavior)
    generic map (
        G_W                     => G_W              ,
        G_DBLK_SIZE             => G_DBLK_SIZE      ,
        G_BS_BYTES              => G_BS_BYTES       ,
        G_TAG_SIZE              => G_TAG_SIZE       ,
        G_REVERSE_DBLK          => G_REVERSE_DBLK   ,
        G_LOADLEN_ENABLE        => G_LOADLEN_ENABLE ,
        G_CIPHERTEXT_MODE       => G_CIPHERTEXT_MODE,
        G_PAD_D                 => PAD_D
    )
    port map (
        --! =================
        --! Global Signals
        --! =================
        --! Global signals
        clk                => clk                   ,
        rst                => rst                   ,

        --! =================
        --! External Signals
        --! =================
        do_ready           => do_ready              ,
        do_valid           => do_valid              ,
        bypass_fifo_data   => bypass_fifo_data      ,
        bypass_fifo_empty  => bypass_fifo_empty     ,
        bypass_fifo_rd     => bypass_fifo_rd        ,
        bdo_ready          => bdo_ready             ,
        bdo_write          => bdo_write             ,
        bdo_size           => bdo_size              ,
        bdo_nsec           => bdo_nsec              ,
        tag_ready          => tag_ready             ,
        tag_write          => tag_write             ,
        msg_auth_done      => msg_auth_done         ,
        msg_auth_valid     => msg_auth_valid        ,

        --! =================
        --! Controls
        --! =================
        bdo_shf             => bdo_shf              ,
        tag_shf             => tag_shf              ,
        sel_instr_actkey    => sel_instr_actkey     ,
        sel_instr_dec       => sel_instr_dec        ,
        sel_hdr             => sel_hdr              ,
        sel_do              => sel_do               ,
        sel_sw              => sel_sw               ,
        sel_sgmt_hdr        => sel_sgmt_hdr         ,
        sel_hword           => sel_hword            ,
        sel_hword_init      => sel_hword_init       ,
        is_i_type           => is_i_type            ,
        is_i_nsec           => is_i_nsec            ,
        msg_id              => msg_id               ,
        key_id              => key_id               ,
        data_bytes          => data_bytes           ,

        en_zeroize          => en_zeroize           ,
        save_size           => save_size            ,
        clr_size            => clr_size             ,
        sel_do2             => sel_do2              ,
        sel_do2_eoi         => sel_do2_eoi          ,
        last_sgmt_size      => last_sgmt_size       ,

        --! =================
        --! FIFO
        --! =================
        aux_fifo_dout       => aux_fifo_dout        ,
        aux_fifo_ctrl       => aux_fifo_ctrl        ,
        aux_fifo_status     => aux_fifo_status
    );
end structure;
