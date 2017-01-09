-------------------------------------------------------------------------------
--! @file       PostProcessor_Datapath.vhd
--! @brief      Datapath unit for post-processor.
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
use ieee.std_logic_unsigned.all;
use ieee.numeric_std.all;
use work.AEAD_pkg.all;

entity PostProcessor_Datapath is
    generic (
        G_W                 : integer := 64;
        G_BS_BYTES          : integer := 4;
        G_DBLK_SIZE         : integer := 128;
        G_TAG_SIZE          : integer := 128;
        G_CIPHERTEXT_MODE   : integer := 0;
        G_REVERSE_DBLK      : integer := 0;
        G_PAD_D             : integer := 0
    );
    port (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk                 : in  std_logic;
        rst                 : in  std_logic;

        --! Data out signals
        do                  : out std_logic_vector(G_W                                -1 downto 0);       --! Output FIFO data

        --! =================
        --! Bypass FIFOs
        --! =================
        bypass_fifo_data    : in  std_logic_vector(G_W                                -1 downto 0);       --! Bypass data

        --! =================
        --! Crypto core
        --! =================
        bdo_write           : in  std_logic;                                                              --! Write data signal
        bdo_data            : in  std_logic_vector(G_DBLK_SIZE                        -1 downto 0);       --! Data from crypto core
        bdo_size            : in  std_logic_vector(G_BS_BYTES+1                       -1 downto 0);       --! Data size
        tag_write           : in  std_logic;                                                              --! Write tag signal
        tag_data            : in  std_logic_vector(G_TAG_SIZE                         -1 downto 0);       --! Data from crypto core
        --! =================
        --! Controller
        --! =================
        bdo_shf             : in  std_logic;                                                              --! Shift output PISO
        tag_shf             : in  std_logic;
        sel_instr_dec       : in  std_logic;                                                              --! Increment instruction Opcode by 1
        sel_instr_actkey    : in  std_logic;                                                              --! Select ACT KEY opcode
        sel_hdr             : in  std_logic;                                                              --! Switch EOI of different segment header
        sel_do              : in  std_logic_vector(  2                                -1 downto 0);       --! Output selection
        sel_sw              : in  std_logic_vector(  2                                -1 downto 0);       --! Segment type encoding selection
        sel_sgmt_hdr        : in  std_logic_vector(  2                                -1 downto 0);       --! Custom header selection
        sel_hword           : in  std_logic;                                                              --! [Special case] Select half word
        sel_hword_init      : in  std_logic;                                                              --! [Special case] Store the left over
        is_i_type           : in  std_logic_vector(  4                                -1 downto 0);       --! Segment type identifier 1 (Cipher/Message)
        is_i_nsec           : in  std_logic_vector(  4                                -1 downto 0);       --! Segment type identifier 2 (Secret number message / Enecrypted secret number message)
        msg_id              : in  std_logic_vector(LEN_MSG_ID                         -1 downto 0);       --! Message ID
        key_id              : in  std_logic_vector(LEN_KEY_ID                         -1 downto 0);       --! Key ID
        data_bytes          : in  std_logic_vector(log2_ceil(G_W/8)                   -1 downto 0);
        en_zeroize          : in  std_logic;

        --! Signals related to CIPHERTEXT_MODE=2
        save_size           : in  std_logic;
        clr_size            : in  std_logic;
        sel_do2             : in  std_logic;
        sel_do2_eoi         : in  std_logic;
        last_sgmt_size      : out std_logic_vector(CTR_SIZE_LIM                       -1 downto 0);

        aux_fifo_din        : out std_logic_vector(G_W                                -1 downto 0);
        aux_fifo_dout       : in  std_logic_vector(G_W                                -1 downto 0)
    );
end PostProcessor_Datapath;

architecture dataflow of PostProcessor_Datapath is
    --! Function and constants declaration
    constant ZEROS              :       std_logic_vector(G_W                                -1 downto 0) := (others => '0');
    constant LOG2_WD8           :       integer                                                          := log2_ceil(G_W/8);
    constant PARTIAL_LOAD       : integer := isNotDivisible(G_DBLK_SIZE, G_W);

    function get_tag_widths(iowidth: integer) return integer is
    begin
        if iowidth-16-LOG2_WD8 >= CTR_SIZE_LIM then
            return CTR_SIZE_LIM;
        else
            return iowidth-16-LOG2_WD8;
        end if;
    end function get_tag_widths;

    constant TAG_WIDTH          :       integer                                                          := get_tag_widths(G_W);       --! Counter width calculation
    constant TAG_WORDS          :       std_logic_vector(TAG_WIDTH                          -1 downto 0)                               --! Calculate the number of words required for the  \
        := std_logic_vector(to_unsigned(get_words(G_TAG_SIZE, G_W), TAG_WIDTH));                                                  --!         specified I/O width and tag size and convert to std_logic_vector
    constant TAG_SIZE           :       std_logic_vector(G_W-16                             -1 downto 0)
        := std_logic_vector(to_unsigned(G_TAG_SIZE/8, G_W-16));
    constant BLOCK_SIZE         :       std_logic_vector(G_W-CTR_SIZE_LIM                   -1 downto 0)
        := std_logic_vector(to_unsigned(G_DBLK_SIZE/8, G_W-CTR_SIZE_LIM));

    signal bdo_reg              :       std_logic_vector(G_DBLK_SIZE                        -1 downto 0);
    signal bdo_word             :       std_logic_vector(G_W                                -1 downto 0);
    signal sgmt_hdr             :       std_logic_vector(G_W                                -1 downto 0);
    signal bypass_fifo_data_sw  :       std_logic_vector(G_W                                -1 downto 0);

    signal enable_word          :       std_logic_vector(G_W                                -1 downto 0);
    signal enable_bytes         :       std_logic_vector(G_W/8                              -1 downto 0);
    signal tag_reg              :       std_logic_vector(G_TAG_SIZE                         -1 downto 0);
    signal tag_word             :       std_logic_vector(G_W                                -1 downto 0);

    signal last_sgmt_size_cntr_dbg        :       std_logic_vector(CTR_SIZE_LIM                 -1 downto 0);
begin
    u_piso:
    process(clk)
    begin
        if rising_edge(clk) then
            if bdo_write = '1' then
                bdo_reg <= bdo_data;
            elsif bdo_shf = '1' then
                bdo_reg <= bdo_reg(G_DBLK_SIZE-G_W-1 downto 0) & ZEROS;
            end if;

            if (G_TAG_SIZE > G_W) then
                if (tag_write = '1') then
                    tag_reg <= tag_data;
                elsif tag_shf = '1' then
                    tag_reg <= tag_reg(G_TAG_SIZE-G_W-1 downto 0) & ZEROS;
                end if;
            elsif (G_TAG_SIZE <= G_W) then
                if (tag_write = '1') then
                    tag_reg <= tag_data;
                end if;
            end if;
        end if;
    end process;
    gPartial0:
    if (PARTIAL_LOAD = 0) generate
        bdo_word <= bdo_reg(G_DBLK_SIZE-1 downto G_DBLK_SIZE-G_W);
    end generate;
    gPartial1:
    if (PARTIAL_LOAD = 1) generate
        signal bdo_half_word_r : std_logic_vector(G_W/2                     -1 downto 0);
    begin
        preg:
        process(clk)
        begin
            if rising_edge(clk) then
                if (bdo_shf = '1') then
                    if (sel_hword_init = '1') then
                        bdo_half_word_r <= bdo_reg(G_DBLK_SIZE-1       downto G_DBLK_SIZE-G_W/2);
                    else
                        bdo_half_word_r <= bdo_reg(G_DBLK_SIZE-G_W/2-1 downto G_DBLK_SIZE-G_W  );
                    end if;
                end if;
            end if;
        end process;
        bdo_word <= bdo_reg(G_DBLK_SIZE-1 downto G_DBLK_SIZE-G_W) when sel_hword = '0' else bdo_half_word_r & bdo_reg(G_DBLK_SIZE-1 downto G_DBLK_SIZE-G_W/2);
    end generate;

    gTagWordCase0:
    if (G_TAG_SIZE > G_W) generate
        tag_word <= tag_reg(G_TAG_SIZE  -1 downto G_TAG_SIZE  -G_W);
    end generate;
    gTagWordCase1:
    if (G_TAG_SIZE = G_W) generate
        tag_word <= tag_reg;
    end generate;
    gTagWordCase2:
    if (G_TAG_SIZE < G_W) generate
        tag_word <= tag_reg & ZEROS(G_W-G_TAG_SIZE-1 downto 0);
    end generate;

    --! Zeroize output data
    gZeroize:
    if (G_CIPHERTEXT_MODE /= 2) generate
        procReg: process(clk)
        begin
            if rising_edge(clk) then
                if en_zeroize = '1' then
                    for i in G_W/8-1 downto 0 loop
                        enable_word(i*8+7 downto i*8) <= (others => enable_bytes(i));
                    end loop;
                else
                    enable_word <= (others => '1');
                end if;
            end if;
        end process;

        uBarrelShifter:
        entity work.bshift(struct)
        generic map (G_W => G_W/8, G_LOG2_W => LOG2_WD8, G_LEFT => 0, G_ROTATE => 0, G_SHIFT1 => 1)
        port map (ii => ZEROS(G_W/8-1 downto 0), rtr => data_bytes, oo => enable_bytes);

        with sel_do select
        aux_fifo_din    <=  bypass_fifo_data_sw      when "00",
                            bdo_word and enable_word when "01",
                            sgmt_hdr                 when "10",
                            tag_word                 when others;
    end generate;
    gNoZeroize:
    if (G_CIPHERTEXT_MODE = 2) generate
        with sel_do select
        aux_fifo_din    <=  bypass_fifo_data_sw      when "00",
                            bdo_word                 when "01",
                            sgmt_hdr                 when "10",
                            tag_word                 when others;
    end generate;

    bypass_fifo_data_sw(G_W- 1 downto G_W- 8)   <= bypass_fifo_data(G_W- 1 downto G_W- 8);
    with sel_sw select
    bypass_fifo_data_sw(G_W- 9 downto G_W-12)   <=
            is_i_type                         when "10",
            is_i_nsec                         when "11",
            bypass_fifo_data(G_W- 9 downto G_W-12) when others;
    bypass_fifo_data_sw(G_W-13 downto G_W-14)   <= bypass_fifo_data(G_W-13 downto G_W-14) when sel_instr_actkey = '0' else "01";

    --! EOI
    sgmt_hdr(G_W-1 downto G_W-LEN_MSG_ID) <= msg_id;
    gPADDnot2: if (G_CIPHERTEXT_MODE /= 2 or G_PAD_D /= 4) generate
        bypass_fifo_data_sw(G_W-15)             <= bypass_fifo_data(G_W-15) when sel_instr_actkey = '0' else '1';
        with sel_sgmt_hdr select
        sgmt_hdr(G_W-LEN_MSG_ID-1 downto 0)     <= "0000" & OP_AE_PASS & key_id & ZEROS(G_W-LEN_MSG_ID-4-LEN_OPCODE-LEN_KEY_ID-1 downto 0) when "10",
                                                   "0000" & OP_AE_FAIL & key_id & ZEROS(G_W-LEN_MSG_ID-4-LEN_OPCODE-LEN_KEY_ID-1 downto 0) when "11",
                                                   ST_TAG     & "0011" & TAG_SIZE                                               when others;
    end generate;
    gPADDis2: if (G_CIPHERTEXT_MODE = 2 and G_PAD_D = 4) generate
        signal selector : std_logic_vector(1 downto 0);
    begin
        selector <= sel_instr_actkey & sel_hdr;
        with selector select
        bypass_fifo_data_sw(G_W-15)             <=     bypass_fifo_data(G_W-15) when "00",
                                                   not bypass_fifo_data(G_W-15) when "01",
                                                                            '1' when others;
        with sel_sgmt_hdr select
        sgmt_hdr(G_W-LEN_MSG_ID-1 downto 0)     <= ST_TAG     & "0011" & TAG_SIZE                                               when "00",
                                                   ST_CIPHER  & "0011" & BLOCK_SIZE                                             when "01",
                                                   "0000" & OP_AE_PASS & key_id & ZEROS(G_W-LEN_MSG_ID-LEN_OPCODE-4-LEN_KEY_ID-1 downto 0) when "10",
                                                   "0000" & OP_AE_FAIL & key_id & ZEROS(G_W-LEN_MSG_ID-LEN_OPCODE-4-LEN_KEY_ID-1 downto 0) when others;
    end generate;

    bypass_fifo_data_sw(G_W-16)            <= bypass_fifo_data(G_W-16)     when (sel_instr_dec = '0' and sel_instr_actkey = '0') else '1';
    bypass_fifo_data_sw(G_W-16-1 downto 0) <= bypass_fifo_data(G_W-16-1 downto 0);


    G_CIPH01: if G_CIPHERTEXT_MODE /= 2 generate
        do <= aux_fifo_dout;
    end generate;

    G_CEXP2 : if G_CIPHERTEXT_MODE = 2 generate
        --! Segment size register (when CIPHERTEXT_MODE = Cexp_T)
        signal last_sgmt_size_cntr         :       std_logic_vector(CTR_SIZE_LIM                 -1 downto 0);
        signal last_sgmt_size_r            :       std_logic_vector(CTR_SIZE_LIM                 -1 downto 0);
    begin
        do(G_W-1                downto G_W-13-1)     <= aux_fifo_dout(G_W-1 downto G_W-13-1);
        do(G_W-14-1)                                 <= aux_fifo_dout(G_W-14-1) when sel_do2_eoi = '0' else '1';
        do(G_W-15-1             downto CTR_SIZE_LIM) <= aux_fifo_dout(G_W-15-1 downto CTR_SIZE_LIM);
        do(CTR_SIZE_LIM-1       downto 0)            <= aux_fifo_dout(CTR_SIZE_LIM-1 downto 0)  when sel_do2 = '0' else last_sgmt_size_r;

        prc:
        process(clk)
        begin
            if rising_edge(clk) then
                if (clr_size = '1') then
                    last_sgmt_size_cntr <= (others => '0');
                elsif (bdo_write = '1') then
                    last_sgmt_size_cntr <= last_sgmt_size_cntr + bdo_size;
                end if;

                if (save_size = '1') then
                    last_sgmt_size_r <= last_sgmt_size_cntr;
                end if;
            end if;
        end process;
        last_sgmt_size     <= last_sgmt_size_r;
        last_sgmt_size_cntr_dbg <= last_sgmt_size_cntr;
    end generate;

end dataflow;
