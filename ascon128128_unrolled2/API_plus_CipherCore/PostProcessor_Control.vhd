-------------------------------------------------------------------------------
--! @file       PostProcessor_Control.vhd
--! @brief      Control unit for post-processor
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

entity PostProcessor_Control is
    generic (
        G_W                     : integer := 64;      --! Output width (bits)
        G_DBLK_SIZE             : integer := 128;     --! Block size (bits)
        G_BS_BYTES              : integer := 4;       --! The number of bits required to hold block size expressed in bytes = log2_ceil(block_size/8)
        G_TAG_SIZE              : integer := 128;     --! Tag size (bits)
        G_REVERSE_DBLK          : integer := 0;       --! Reverse order of message block
        G_CIPHERTEXT_MODE       : integer := 0;       --! Ciphertext processing mode
        G_LOADLEN_ENABLE        : integer := 0;    --! Enable load length section
        G_PAD_D                 : integer := 0        --! Padding of data block
    );
    port (
        --! =================
        --! Global Signals
        --! =================
        --! Global signals
        clk                 : in  std_logic;
        rst                 : in  std_logic;

        --! =================
        --! External Signals
        --! =================
        do_ready            : in  std_logic;                                                           --! Output FIFO ready
        do_valid            : out std_logic;
        bypass_fifo_data    : in  std_logic_vector(G_W                                -1 downto 0);    --! Bypass FIFO data
        bypass_fifo_empty   : in  std_logic;                                                           --! Bypass FIFO empty
        bypass_fifo_rd      : out std_logic;                                                           --! Bypass FIFO read
        bdo_ready           : out std_logic;                                                           --! Output BDO ready (Let crypto core knows that it's ready to accept data)
        bdo_write           : in  std_logic;                                                           --! Write to output BDO
        bdo_size            : in  std_logic_vector(G_BS_BYTES+1                       -1 downto 0);    --! Data size
        bdo_nsec            : in  std_logic;                                                           --! Nsec flag
        tag_ready           : out std_logic;                                                           --! Output TAG ready (Let crypto core knows that it's ready to accept data)
        tag_write           : in  std_logic;                                                           --! Write to output TAG
        msg_auth_done       : in  std_logic;
        msg_auth_valid      : in  std_logic;

        --! =================
        --! Controls
        --! =================
        bdo_shf             : out std_logic;                                                           --! Shift output BDO
        tag_shf             : out std_logic;                                                           --! Shift tag register
        sel_instr_dec       : out std_logic;                                                           --! Increment instruction Opcode by 1
        sel_instr_actkey    : out std_logic;                                                           --! Select ACT KEY opcode
        sel_hdr             : out std_logic;                                                           --! Switch EOI of different segment header
        sel_do              : out std_logic_vector(  2                                -1 downto 0);    --! Output selection
        sel_sw              : out std_logic_vector(  2                                -1 downto 0);    --! Segment type encoding selection
        sel_sgmt_hdr        : out std_logic_vector(  2                                -1 downto 0);    --! Select custom header
        sel_hword           : out std_logic;                                                           --! [Special case] Select half word
        sel_hword_init      : out std_logic;                                                           --! [Special case] Store the left over
        is_i_type           : out std_logic_vector(  4                                -1 downto 0);    --! Segment type identifier 1 (Cipher/Message)
        is_i_nsec           : out std_logic_vector(  4                                -1 downto 0);    --! Segment type identifier 2 (Secret number message / Enecrypted secret number message)
        msg_id              : out std_logic_vector(LEN_MSG_ID                         -1 downto 0);    --! Message ID
        key_id              : out std_logic_vector(LEN_KEY_ID                         -1 downto 0);    --! Key ID
        data_bytes          : out std_logic_vector(log2_ceil(G_W/8)                   -1 downto 0);    --! Data size
        en_zeroize          : out std_logic;                                                           --! Enable zeroization

        --!     CIPHERTEXT_MODE=2
        save_size           : out std_logic;
        clr_size            : out std_logic;
        sel_do2             : out std_logic;
        sel_do2_eoi         : out std_logic;
        last_sgmt_size      : in  std_logic_vector(CTR_SIZE_LIM                       -1 downto 0);

        aux_fifo_dout       : in  std_logic_vector(G_W                                -1 downto 0);
        aux_fifo_ctrl       : out std_logic_vector(4                                  -1 downto 0);
        aux_fifo_status     : in  std_logic_vector(3                                  -1 downto 0)
    );
end PostProcessor_Control;

architecture behavior of PostProcessor_Control is
    --! Function and constants declaration
    function get_bdo_count_width  return integer is
    begin
        if G_CIPHERTEXT_MODE = 2 then
            return G_BS_BYTES+1;
        else
            return G_BS_BYTES;
        end if;
    end function get_bdo_count_width;

    constant PARTIAL_LOAD       : integer                                  := isNotDivisible(G_DBLK_SIZE, G_W);
    constant LOG2_WD8           : integer                                  := log2_ceil(G_W/8);
    constant ONES               : std_logic_vector(G_DBLK_SIZE-1 downto 0) := (others => '1');
    constant ZEROS              : std_logic_vector(G_DBLK_SIZE-1 downto 0) := (others => '0');
    constant CNTR_WIDTH         : integer                                  := get_cntr_width(G_W);
    constant BDO_COUNT_WIDTH    : integer                                  := get_bdo_count_width;

    type state_type     is (S_WAIT_INSTR, S_READ_INSTR, S_GEN_SUCC_HDR,
                            S_GEN_ACT_KEY_DELAY, S_WAIT_HDR, S_READ_HDR,
                            S_WAIT_BYPASS, S_WAIT_BDO, S_GEN_TAG_HDR,
                            S_WRITE_TAG, S_GEN_CIPH_HDR, S_WAIT_MSG_AUTH,
                            S_WRITE_TAG_ERROR, S_ERROR);

    signal state                : state_type;
    signal nstate               : state_type;

    signal fifo_write_pre       : std_logic;
    signal fifo_write_now       : std_logic;
    signal fifo_write_r         : std_logic;
    signal sel_do_pre           : std_logic_vector(  2                                -1 downto 0);
    signal sel_sgmt_hdr_pre     : std_logic_vector(  2                                -1 downto 0);

    signal tag_count            : std_logic_vector(log2_ceil(G_TAG_SIZE/8)            -1 downto 0);
    signal tag_empty            : std_logic;
    signal tag_shf_pre          : std_logic;

    signal bdo_count            : std_logic_vector(BDO_COUNT_WIDTH                    -1 downto 0);
    signal bdo_empty            : std_logic;
    signal bdo_shf_pre          : std_logic;
    signal bdo_clr_pre          : std_logic;

    signal opcode               : std_logic_vector(  4                                -1 downto 0);
    signal sgmt_stype           : std_logic_vector(  4                                -1 downto 0);
    signal sgmt_eoi             : std_logic;
    signal sgmt_eot             : std_logic;

    signal en_instr_flag        : std_logic;
    signal is_decrypt           : std_logic;
    signal is_ae                : std_logic;
    signal is_ad                : std_logic;
    signal en_sgmt_status       : std_logic;
    signal clr_hdr_status       : std_logic;

    signal instr_decrypt        : std_logic;
    signal sgmt_msg_type        : std_logic_vector(  4                                -1 downto 0);
    signal sgmt_nsec_type       : std_logic_vector(  4                                -1 downto 0);
    signal sgmt_nsec_flag       : std_logic;
    signal msg_end              : std_logic;
    signal msg_id_r             : std_logic_vector(LEN_MSG_ID                         -1 downto 0);
    signal key_id_r             : std_logic_vector(LEN_KEY_ID                         -1 downto 0);

    signal counter_load_tag     : std_logic;
    signal counter_load_block   : std_logic;
    signal counter_load         : std_logic;
    signal counter_en           : std_logic;
    signal sgmt_size            : std_logic_vector(CNTR_WIDTH                         -1 downto 0);

    signal sw_stype             : std_logic;
    signal sw_nsec              : std_logic;

    signal hold_output          : std_logic;
    signal clr_hold_output      : std_logic;
    signal restore_state        : std_logic;

    signal clr_status           : std_logic;
    signal set_sgmt_tag_flag    : std_logic;
    signal sgmt_tag_flag        : std_logic;
    signal set_sgmt_tag_passed  : std_logic;
    signal sgmt_tag_passed      : std_logic;

    signal set_no_write         : std_logic;
    signal no_write             : std_logic;

    signal msg_auth_done_r      : std_logic;
    signal msg_auth_valid_r     : std_logic;

    --! Partial data related signals
    signal toggle_partial       : std_logic;
    signal clr_partial          : std_logic;
    signal is_partial           : std_logic;

    signal fifo_save_state      : std_logic;
    signal fifo_restore_state   : std_logic;
    signal fifo_write           : std_logic;
    signal fifo_read            : std_logic;
    signal fifo_unread_avail    : std_logic;
    signal fifo_empty           : std_logic;
    signal fifo_full            : std_logic;
begin
    fifo_unread_avail   <= aux_fifo_status(0);
    fifo_empty          <= aux_fifo_status(1);
    fifo_full           <= aux_fifo_status(2);
    aux_fifo_ctrl       <= fifo_read & fifo_write & fifo_restore_state & fifo_save_state;

    --! Output
    sel_sw              <= sw_stype & sw_nsec;
    gPartial:
    if (PARTIAL_LOAD = 1) generate
        sel_hword           <= is_partial;
    end generate;
    is_i_type           <= sgmt_msg_type;
    is_i_nsec           <= sgmt_nsec_type;
    msg_id              <= msg_id_r;
    key_id              <= key_id_r;

    fifo_save_state     <= is_decrypt;
    fifo_restore_state  <= restore_state;

    --! Format decoder
    opcode              <= bypass_fifo_data(G_W-12-1 downto G_W-16);
    sgmt_stype          <= bypass_fifo_data(G_W- 8-1 downto G_W-12);
    sgmt_eot            <= bypass_fifo_data(G_W-15-1);
    sgmt_eoi            <= bypass_fifo_data(G_W-14-1);

    data_bytes          <= sgmt_size(log2_ceil(G_W/8)-1 downto 0);

    --! Registers
    procRegs:
    process( clk )
    begin
        if rising_edge( clk ) then
            if rst = '1' then
                state           <= S_WAIT_INSTR;
                sgmt_msg_type   <= (others => '0');
                msg_end         <= '0';
                sgmt_size       <= (others => '0');
                msg_id_r        <= (others => '0');
                bdo_empty       <= '1';
                tag_empty       <= '1';
                hold_output     <= '0';
                msg_auth_done_r <= '0';
                tag_count       <= (others => '0');
                bdo_count       <= (others => '0');
                no_write        <= '0';
                fifo_write_r    <= '0';
                sgmt_tag_passed <= '0';
                msg_auth_valid_r <= '0';
            else
                state <= nstate;
                if en_instr_flag = '1' then
                    msg_id_r  <= bypass_fifo_data(G_W-1 downto G_W-LEN_MSG_ID);
                    key_id_r  <= bypass_fifo_data(G_W-LEN_MSG_ID-4-LEN_OPCODE-1 downto G_W-LEN_MSG_ID-4-LEN_OPCODE-LEN_KEY_ID);
                    if is_decrypt = '1' then
                        sgmt_msg_type     <= ST_MESSAGE;
                        sgmt_nsec_type    <= ST_NSEC;
                        instr_decrypt     <= '1';
                    else
                        sgmt_msg_type     <= ST_CIPHER;
                        sgmt_nsec_type    <= ST_NSEC_CIPH;
                        instr_decrypt     <= '0';
                    end if;
                end if;

                if (en_instr_flag = '1') then
                    if ((is_decrypt = '1') or (G_CIPHERTEXT_MODE = 2)) then
                        hold_output <= '1';
                    else
                        hold_output <= '0';
                    end if;
                elsif (clr_hold_output = '1') then
                    hold_output <= '0';
                end if;

                if clr_hdr_status = '1' then
                    msg_end   <= '0';
                elsif en_sgmt_status = '1' then
                    msg_end   <= sgmt_eoi;
                end if;

                if counter_load_tag = '1' then
                    sgmt_size <= std_logic_vector(to_unsigned(G_TAG_SIZE/8,  CNTR_WIDTH));
                elsif (G_CIPHERTEXT_MODE = 2 and G_PAD_D = 4 and counter_load_block = '1') then
                    --! Special case for when Msg = 0 in G_CIPHERTEXT_MODE and G_PAD_D = 2
                    sgmt_size <= std_logic_vector(to_unsigned(G_DBLK_SIZE/8, CNTR_WIDTH));
                elsif counter_load = '1' then
                    if (G_CIPHERTEXT_MODE = 2) then
                        if (sgmt_stype = ST_MESSAGE and sgmt_eoi = '1' and G_REVERSE_DBLK = 0) then
                            sgmt_size <= (bypass_fifo_data(CNTR_WIDTH-1 downto G_BS_BYTES) + 1) & ZEROS(G_BS_BYTES-1 downto 0);
                        else
                            sgmt_size <= bypass_fifo_data(CNTR_WIDTH-1 downto 0);
                        end if;
                    else
                        sgmt_size <= bypass_fifo_data(CNTR_WIDTH-1 downto 0);
                    end if;
                elsif counter_en = '1' then
                    sgmt_size <= sgmt_size - G_W/8;
                end if;

                if state = S_READ_HDR then
                    if sw_nsec = '1' then
                        sgmt_nsec_flag <= '1';
                    else
                        sgmt_nsec_flag <= '0';
                    end if;
                end if;

                --! Keeps track whether the BDO register is empty
                if (bdo_write = '1') then
                    bdo_empty      <= '0';
                elsif ((bdo_count = 0) or
                       (G_CIPHERTEXT_MODE = 2 and bdo_count <= G_W/8 and bdo_shf_pre = '1') or
                       (sgmt_size <= G_W/8 and bdo_shf_pre = '1') or
                       (bdo_clr_pre = '1'))
                then
                    bdo_empty      <= '1';
                end if;

                --! Keeps track of available bytes in BDO register
                if (G_CIPHERTEXT_MODE /= 2) then
                    if (bdo_write = '1') then
                        if (PARTIAL_LOAD = 1) then
                            bdo_count         <= std_logic_vector(to_unsigned(((G_DBLK_SIZE+G_W-1)/G_W), G_BS_BYTES));
                        else
                            bdo_count         <= std_logic_vector(to_unsigned(G_DBLK_SIZE/G_W-1, G_BS_BYTES));
                        end if;
                    elsif (bdo_shf_pre = '1') then
                        bdo_count         <= bdo_count - 1;
                    end if;
                else
                    if (bdo_write = '1') then
                        bdo_count         <= bdo_size;
                    elsif (bdo_shf_pre = '1') then
                        if (bdo_count > G_W/8) then
                            bdo_count     <= bdo_count - G_W/8;
                        else
                            bdo_count     <= (others => '0');
                        end if;
                    end if;
                end if;

                --! Keeps track whether the TAG register is empty
                if (tag_write = '1') then
                    tag_empty         <= '0';
                elsif (G_TAG_SIZE > G_W and ((tag_shf_pre = '1' and sgmt_size = 1) or (tag_count = 0 and tag_shf_pre = '1'))) or
                      (G_TAG_SIZE <= G_W and (sel_do_pre = "11"))
                then
                    tag_empty         <= '1';
                end if;

                --! Keeps track of available bytes in TAG register
                if (G_TAG_SIZE > G_W) then
                    if (tag_write = '1') then
                        tag_count         <= std_logic_vector(to_unsigned(G_TAG_SIZE/G_W-1, log2_ceil(G_TAG_SIZE/8)));
                    elsif (tag_shf_pre = '1') then
                        tag_count         <= tag_count - 1;
                    end if;
                end if;


                if (set_sgmt_tag_flag = '1') then
                    sgmt_tag_flag     <= '1';
                elsif (clr_status = '1') then
                    sgmt_tag_flag     <= '0';
                end if;

                if (set_no_write = '1') then
                    no_write          <= '1';
                elsif (clr_status = '1') then
                    no_write          <= '0';
                end if;

                if (set_sgmt_tag_passed = '1') then
                    sgmt_tag_passed   <= '1';
                elsif (clr_status = '1') then
                    sgmt_tag_passed   <= '0';
                end if;

                --! Capture the tag comparison flag and result
                if (clr_hold_output = '1') then
                    msg_auth_done_r   <= '0';
                elsif (msg_auth_done = '1') then
                    msg_auth_done_r   <= '1';
                    msg_auth_valid_r  <= msg_auth_valid;
                end if;

                if (PARTIAL_LOAD = 1) then
                    if (toggle_partial = '1') then
                        is_partial <= not is_partial;
                    elsif (clr_partial = '1') then
                        is_partial <= '0';
                    end if;
                    if (toggle_partial = '1' and is_partial = '0') then
                        sel_hword_init <= '1';
                    else
                        sel_hword_init <= '0';
                    end if;
                end if;

                if (G_TAG_SIZE > G_W) then
                    tag_shf       <= tag_shf_pre;
                end if;
                bdo_shf       <= bdo_shf_pre;
                sel_do        <= sel_do_pre;
                fifo_write_r  <= fifo_write_pre;
                sel_sgmt_hdr  <= sel_sgmt_hdr_pre;
            end if;
        end if;
    end process;
    fifo_write <= fifo_write_r or fifo_write_now;

    --! Controller
    procFSM:
    process( state, bypass_fifo_empty, bypass_fifo_data, bdo_empty, bdo_write, fifo_full, sgmt_nsec_flag,
             sgmt_size, opcode, sgmt_stype, msg_end, hold_output, sgmt_tag_flag, bdo_count, is_partial,
             tag_empty, msg_auth_valid_r, msg_auth_done_r, instr_decrypt, no_write)
    begin
        sel_do_pre          <= "00";
        fifo_write_pre      <= '0';
        fifo_write_now      <= '0';
        bypass_fifo_rd      <= '0';
        is_ae               <= '0';
        is_ad               <= '0';
        is_decrypt          <= '0';
        en_instr_flag       <= '0';
        en_sgmt_status      <= '0';
        clr_hdr_status      <= '0';
        counter_load_tag    <= '0';
        if (G_CIPHERTEXT_MODE = 2) then
            counter_load_block  <= '0';
            clr_size            <= '0';
            save_size           <= '0';
        end if;
        if (PARTIAL_LOAD = 1) then
            toggle_partial      <= '0';
            clr_partial         <= '0';
        end if;
        counter_load        <= '0';
        counter_en          <= '0';
        sw_stype            <= '0';
        sel_instr_dec        <= '0';
        sel_instr_actkey    <= '0';
        sel_hdr             <= '0';
        sel_sgmt_hdr_pre    <= "00";
        sw_nsec             <= '0';
        bdo_shf_pre         <= '0';
        bdo_clr_pre         <= '0';
        restore_state       <= '0';
        clr_hold_output     <= '0';
        if (G_TAG_SIZE > G_W) then
            tag_shf_pre         <= '0';
        end if;
        set_sgmt_tag_flag   <= '0';
        set_sgmt_tag_passed <= '0';
        clr_status          <= '0';
        en_zeroize          <= '0';
        set_no_write        <= '0';
        nstate              <= state;

        case state is
            when S_WAIT_INSTR =>
                if (bypass_fifo_empty = '0' and fifo_full = '0') then
                    nstate               <= S_READ_INSTR;
                    bypass_fifo_rd       <= '1';
                    clr_hdr_status       <= '1';
                    bdo_clr_pre          <= '1';
                    clr_status           <= '1';
                    clr_hold_output      <= '1';
                end if;

            when S_READ_INSTR =>
                if (opcode = OP_ACT_KEY) then
                    nstate              <= S_WAIT_INSTR;
                else
                    if (opcode = OP_AE_DEC or opcode = OP_DEC) then
                        nstate           <= S_GEN_SUCC_HDR;
                    else
                        --! Generate ACT_KEY instruction word
                        nstate           <= S_GEN_ACT_KEY_DELAY;
                        fifo_write_now   <= '1';
                        sel_instr_actkey <= '1';
                    end if;
                    en_instr_flag        <= '1';
                end if;
                if (opcode = OP_AE_ENC or opcode = OP_AE_DEC) then
                    is_ae                <= '1';
                end if;
                if (opcode = OP_AE_DEC or opcode = OP_DEC) then
                    is_decrypt           <= '1';
                end if;
                -- if (opcode = OP_AE_ENC or opcode = OP_ENC) then
                    -- fifo_write_now      <= '1';
                    -- sel_instr_dec           <= '1';
                -- end if;

            when S_GEN_ACT_KEY_DELAY =>
                --! Generate Decryption instruction word
                nstate              <= S_WAIT_HDR;
                fifo_write_now      <= '1';
                sel_instr_dec       <= '1';

            when S_GEN_SUCC_HDR =>
                --! Generate a success header
                --! Note: Created in a different cycle than the read_instr
                --!       because we need to save the state first.
                nstate              <= S_WAIT_HDR;
                fifo_write_pre      <= '1';
                sel_do_pre          <= "10";
                sel_sgmt_hdr_pre    <= "10";

            when S_WAIT_HDR =>
                if (bypass_fifo_empty = '0' and fifo_full = '0') then
                    nstate              <= S_READ_HDR;
                    bypass_fifo_rd      <= '1';
                end if;

            when S_READ_HDR =>
                if (instr_decrypt = '1' and (
                    (sgmt_stype = ST_TAG and G_CIPHERTEXT_MODE /= 2) or
                    (sgmt_stype = ST_NPUB) or
                    (G_LOADLEN_ENABLE = 1 and sgmt_stype = ST_LEN))
                   )
                then
                    fifo_write_now      <= '0';
                else
                    fifo_write_now      <= '1';
                end if;
                counter_load        <= '1';
                en_sgmt_status      <= '1';

                --! Special settings
                if (G_CIPHERTEXT_MODE = 2) then
                    clr_size            <= '1';
                end if;
                if (PARTIAL_LOAD = 1) then
                    clr_partial         <= '1';
                end if;

                if (sgmt_stype = ST_MESSAGE or sgmt_stype = ST_CIPHER) then
                    sw_stype            <= '1';
                    nstate              <= S_WAIT_BDO;
                elsif (sgmt_stype = ST_NSEC or sgmt_stype = ST_NSEC_CIPH) then
                    sw_stype            <= '1';
                    sw_nsec             <= '1';
                    nstate              <= S_WAIT_BDO;
                elsif (sgmt_stype = ST_NPUB or (G_LOADLEN_ENABLE = 1 and sgmt_stype = ST_LEN)) then
                    nstate              <= S_WAIT_BYPASS;
                    if (instr_decrypt = '1') then
                        set_no_write    <= '1';
                    end if;
                elsif (sgmt_stype = ST_AD) then
                    is_ad               <= '1';
                    nstate              <= S_WAIT_BYPASS;
                    if (G_CIPHERTEXT_MODE = 2 and G_PAD_D = 4 and instr_decrypt = '0' and sgmt_eoi = '1') then
                        sel_hdr         <= '1';
                    end if;
                elsif (sgmt_stype = ST_TAG) then
                    if (sgmt_eoi = '1') then
                        set_sgmt_tag_flag   <= '1';
                    end if;
                    set_sgmt_tag_passed <= '1';
                    if (sgmt_eoi = '1' and instr_decrypt = '1') then
                        if (G_CIPHERTEXT_MODE = 2) then
                            save_size       <= '1';
                        end if;
                        nstate          <= S_WAIT_MSG_AUTH;
                    else
                        nstate          <= S_WAIT_HDR;
                    end if;
                else
                    nstate              <= S_ERROR;
                end if;

            when S_WAIT_BYPASS =>
                if (bypass_fifo_empty = '0' and fifo_full = '0') then
                    counter_en      <= '1';
                    bypass_fifo_rd  <= '1';
                    if (sgmt_tag_flag = '0' and  --! No output write if, sgmt = tag
                        no_write = '0')          --! No output write if, sgmt = IV and decrypt = 1
                    then
                        fifo_write_pre      <= '1';
                    end if;

                    if sgmt_size <= G_W/8 then
                        clr_status <= '1';
                        if msg_end = '1' then
                            if (G_CIPHERTEXT_MODE = 2 and G_PAD_D = 4 and instr_decrypt = '0') then
                                nstate  <= S_GEN_CIPH_HDR;
                            elsif  (sgmt_tag_flag = '0') and --! Special case: No message / no AD
                                (instr_decrypt = '0')     --! Special case: No message
                            then
                                nstate  <= S_GEN_TAG_HDR;
                            else
                                if (sgmt_tag_passed = '1') then
                                    nstate  <= S_WAIT_MSG_AUTH;
                                else
                                    nstate  <= S_WAIT_HDR;
                                end if;
                            end if;
                        else
                            nstate  <= S_WAIT_HDR;
                        end if;
                    end if;
                end if;

            when S_WAIT_BDO =>
                if (bdo_empty = '0' and fifo_full = '0') then
                    bdo_shf_pre     <= '1';
                    if (G_CIPHERTEXT_MODE = 2) then
                        if (bdo_count /= 0) then
                            fifo_write_pre  <= '1';
                        end if;
                        counter_en      <= '1';
                    elsif (PARTIAL_LOAD = 1) then
                        if (bdo_count > 1) or
                            (bdo_count = 1 and is_partial = '0' and sgmt_size <= ((G_W/8)/2)) or
                            --(bdo_count = 1 and is_partial = '1' and sgmt_size <= (G_W/8))
                            (bdo_count = 1 and is_partial = '1')
                        then
                            fifo_write_pre <= '1';
                            counter_en     <= '1';
                        end if;
                        if (bdo_count = 1 and is_partial = '0' and sgmt_size > (G_W/8)/2) or
                           (bdo_count = 0 and is_partial = '1' and sgmt_size > (G_W/8)/2)
                        then
                            toggle_partial <= '1';
                        end if;
                    else
                        fifo_write_pre  <= '1';
                        counter_en      <= '1';
                    end if;
                    sel_do_pre      <= "01";

                    if (sgmt_size < G_W/8) then
                        en_zeroize <= '1';
                    end if;

                    if ((sgmt_size <= G_W/8) or
                        (G_CIPHERTEXT_MODE = 2 and (bdo_count = 0 or bdo_count <= G_W/8) and instr_decrypt = '1' and sgmt_size <= G_DBLK_SIZE/8) or
                        (PARTIAL_LOAD = 1 and bdo_count = 1 and is_partial = '0' and sgmt_size > (G_W/8)/2))
                    then
                        bdo_clr_pre <= '1';
                    end if;

                    if ((sgmt_size <= G_W/8) or
                        (G_CIPHERTEXT_MODE = 2 and (bdo_count = 0 or bdo_count <= G_W/8) and instr_decrypt = '1' and sgmt_size <= G_DBLK_SIZE/8))
                    then
                        if (PARTIAL_LOAD = 1 and bdo_count = 1 and is_partial = '0' and sgmt_size > (G_W/8)/2) then
                            --! Do nothing, stay in the same state and wait for next block
                            nstate <= S_WAIT_BDO;
                        elsif (msg_end = '1') then
                            if (sgmt_nsec_flag = '0') then
                                if instr_decrypt = '1' then
                                    if (G_CIPHERTEXT_MODE = 2 and G_REVERSE_DBLK = 1) then
                                        --! Special state change for PRIMATEs-APE
                                        nstate      <= S_WAIT_MSG_AUTH;
                                        save_size   <= '1';
                                    else
                                        nstate  <= S_WAIT_HDR;
                                    end if;
                                else
                                    nstate  <= S_GEN_TAG_HDR;
                                end if;
                            elsif sgmt_nsec_flag = '1' then
                                nstate  <= S_WAIT_HDR;
                            else
                                if (G_CIPHERTEXT_MODE = 2) then
                                    save_size       <= '1';
                                end if;
                                nstate  <= S_WAIT_INSTR;
                            end if;
                        else
                            nstate      <= S_WAIT_HDR;
                        end if;
                    end if;
                end if;

            when S_GEN_TAG_HDR  =>
                nstate              <= S_WRITE_TAG;
                fifo_write_pre      <= '1';
                sel_do_pre          <= "10";
                counter_load_tag    <= '1';

            when S_GEN_CIPH_HDR =>
                nstate              <= S_WAIT_BDO;
                fifo_write_pre      <= '1';
                sel_do_pre          <= "10";
                sel_sgmt_hdr_pre    <= "01";
                if (G_CIPHERTEXT_MODE = 2) then
                    counter_load_block  <= '1';
                end if;

            when S_WRITE_TAG =>
                if (tag_empty = '0' and fifo_full = '0') then
                    if (G_TAG_SIZE > G_W) then
                        tag_shf_pre    <= '1';
                    end if;
                    sel_do_pre      <= "11";
                    if (sgmt_size /= 0) then
                        counter_en      <= '1';
                    end if;
                    fifo_write_pre  <= '1';
                    if (sgmt_size <= G_W/8) then
                        if (G_CIPHERTEXT_MODE = 2) then
                            clr_hold_output <= '1';
                            save_size       <= '1';
                        end if;
                        nstate          <= S_WAIT_INSTR;
                    end if;
                end if;

            when S_WAIT_MSG_AUTH =>
                if (msg_auth_done_r = '1') then
                    if (msg_auth_valid_r = '1') then
                        nstate          <= S_WAIT_INSTR;
                        clr_hold_output <= '1';
                    else
                        restore_state   <= '1';
                        nstate          <= S_WRITE_TAG_ERROR;
                    end if;
                end if;

            when S_WRITE_TAG_ERROR =>
                clr_hold_output  <= '1';
                sel_do_pre       <= "10";
                sel_sgmt_hdr_pre <= "11";
                fifo_write_pre   <= '1';
                nstate           <= S_WAIT_INSTR;

            when S_ERROR =>

        end case;
    end process;

    bdo_ready <= bdo_empty;
    tag_ready <= tag_empty;


    G_CIPH01: if G_CIPHERTEXT_MODE /= 2 generate
        signal fifo_read_s : std_logic;
    begin
        process(clk)
        begin
            if rising_edge(clk) then
                do_valid <= fifo_read_s;
            end if;
        end process;
        fifo_read_s <= '1' when (fifo_empty = '0' and do_ready = '1' and (hold_output = '0' or fifo_unread_avail = '1')) else '0';
        fifo_read   <= fifo_read_s;
    end generate;

    G_CEXP2 : if G_CIPHERTEXT_MODE = 2 generate
        type ostate_type is (S_READ_INSTR, S_WRITE_INSTR, S_READ_HDR, S_WRITE_HDR,
                             S_READ_DATA_INIT, S_READ_DATA, S_WRITE_LAST_WORD);
        signal ostate, n_ostate         : ostate_type;
        signal save_instr_status        : std_logic;
        signal save_sgmt_status         : std_logic;
        signal aux_opcode               : std_logic_vector(  4                                -1 downto 0);
        signal aux_sgmt_stype           : std_logic_vector(  4                                -1 downto 0);
        signal aux_sgmt_eoi             : std_logic;
        signal aux_sgmt_eot             : std_logic;
        signal aux_sgmt_stype_r         : std_logic_vector(  4                                -1 downto 0);
        signal aux_sgmt_eoi_r           : std_logic;
        signal aux_sgmt_eot_r           : std_logic;
        signal aux_instr_decrypt_r      : std_logic;
        signal switch_sgmt_size         : std_logic;
        signal switch_sgmt_eoi          : std_logic;
        signal aux_sgmt_cntr            : std_logic_vector(CNTR_WIDTH                         -1 downto 0);
        signal aux_sgmt_cntr_en         : std_logic;

        signal aux_sgmt_tag_passed      : std_logic;
        signal set_aux_sgmt_tag_passed  : std_logic;
    begin
        aux_opcode        <= aux_fifo_dout(G_W-12-1 downto G_W-16);
        aux_sgmt_stype    <= aux_fifo_dout(G_W- 8-1 downto G_W-12);
        aux_sgmt_eot      <= aux_fifo_dout(G_W-15-1);
        aux_sgmt_eoi      <= aux_fifo_dout(G_W-14-1);
        sel_do2           <= switch_sgmt_size;
        sel_do2_eoi       <= switch_sgmt_eoi;
        pState:
        process(clk)
        begin
            if rising_edge(clk) then
                if rst = '1' then
                    ostate <= S_READ_INSTR;
                else
                    ostate <= n_ostate;
                end if ;

                if (save_instr_status = '1') then
                    if (aux_opcode = OP_AE_PASS) then
                        aux_instr_decrypt_r <= '1';
                    else
                        aux_instr_decrypt_r <= '0';
                    end if;
                end if;

                if (set_aux_sgmt_tag_passed = '1') then
                    aux_sgmt_tag_passed <= '1';
                elsif (save_instr_status = '1') then
                    aux_sgmt_tag_passed <= '0';
                end if;

                if (save_sgmt_status = '1') then
                    aux_sgmt_eot_r   <= aux_sgmt_eot;
                    aux_sgmt_eoi_r   <= aux_sgmt_eoi;
                    aux_sgmt_stype_r <= aux_sgmt_stype;

                    if switch_sgmt_size = '1' then
                        aux_sgmt_cntr <= last_sgmt_size;
                    else
                        aux_sgmt_cntr <= aux_fifo_dout(CNTR_WIDTH-1 downto 0);
                    end if;
                elsif aux_sgmt_cntr_en = '1' then
                    if (aux_sgmt_cntr >= G_W/8) then
                        aux_sgmt_cntr <= aux_sgmt_cntr - G_W/8;
                    else
                        aux_sgmt_cntr <= (others => '0');
                    end if;
                end if;
            end if;
        end process;

        pState2:
        process( ostate, fifo_empty, do_ready, hold_output, last_sgmt_size, aux_opcode, aux_sgmt_tag_passed, 
                aux_instr_decrypt_r, aux_sgmt_eoi, aux_sgmt_eoi_r, aux_sgmt_eot,  aux_sgmt_cntr,
                aux_sgmt_stype, aux_sgmt_stype_r)
        begin
            n_ostate                <= ostate;

            fifo_read               <= '0';
            do_valid                <= '0';
            save_instr_status       <= '0';
            save_sgmt_status        <= '0';
            switch_sgmt_size        <= '0';
            switch_sgmt_eoi         <= '0';
            aux_sgmt_cntr_en        <= '0';
            set_aux_sgmt_tag_passed <= '0';

            case ostate is
                when S_READ_INSTR =>
                    if ((fifo_empty = '0') and (hold_output = '0')) then
                        fifo_read <= '1';
                        n_ostate <= S_WRITE_INSTR;
                    end if;
                when S_WRITE_INSTR =>
                    save_instr_status <= '1';
                    if (do_ready = '1') then
                        do_valid <= '1';
                        if (aux_opcode = OP_AE_DEC or aux_opcode = OP_AE_PASS) then
                            n_ostate <= S_READ_HDR;
                        else
                            n_ostate <= S_READ_INSTR;
                        end if;
                    end if;
                when S_READ_HDR =>
                    if (fifo_empty = '0') then
                        fifo_read         <= '1';
                        n_ostate          <= S_WRITE_HDR;
                    end if;
                when S_WRITE_HDR =>
                    if (do_ready = '1') then
                        save_sgmt_status      <= '1';
                        --! Switch to a real size if it's the last segment header for decryption
                        --! Note: For encryption, the size has been adjusted in the previous stage.
                        if (aux_sgmt_eoi = '1' 
                            and (aux_sgmt_stype = ST_MESSAGE or aux_sgmt_stype = ST_CIPHER)) 
                        then
                            switch_sgmt_size  <= '1';
                        end if;
                        if (aux_instr_decrypt_r = '1' and aux_sgmt_eot = '1' 
                            and aux_sgmt_stype = ST_AD and last_sgmt_size = 0) 
                        then
                            switch_sgmt_eoi   <= '1';
                        end if;

                        if (aux_instr_decrypt_r = '1' and aux_sgmt_eoi = '1' and aux_sgmt_stype /= ST_AD) then
                            if ((aux_sgmt_tag_passed = '1' and last_sgmt_size = 0) or aux_sgmt_stype = ST_TAG) then
                                n_ostate                <= S_READ_INSTR;
                            elsif (last_sgmt_size /= 0) then
                                n_ostate                <= S_READ_DATA_INIT;
                                do_valid                <= '1';
                            elsif (fifo_empty = '0') then
                                n_ostate                <= S_READ_HDR;
                            end if;
                        else
                            if (aux_sgmt_stype = ST_TAG and aux_instr_decrypt_r = '1') then
                                n_ostate                <= S_READ_HDR;
                                set_aux_sgmt_tag_passed <= '1';
                            else
                                n_ostate                <= S_READ_DATA_INIT;
                                do_valid                <= '1';
                            end if;
                        end if;
                    end if;
                when S_READ_DATA_INIT =>
                    if (fifo_empty = '0') then
                        fifo_read        <= '1';
                        aux_sgmt_cntr_en <= '1';
                        if (aux_sgmt_cntr <= G_W/8) then
                            n_ostate <= S_WRITE_LAST_WORD;
                        else
                            n_ostate <= S_READ_DATA;
                        end if;
                    end if;
                when S_READ_DATA =>
                    if (fifo_empty = '0' and do_ready = '1') then
                        fifo_read        <= '1';
                        aux_sgmt_cntr_en <= '1';
                        do_valid         <= '1';
                        if (aux_sgmt_cntr <= G_W/8) then
                            n_ostate <= S_WRITE_LAST_WORD;
                        end if;
                    end if;
                when S_WRITE_LAST_WORD =>
                    if (do_ready = '1') then
                        do_valid <= '1';
                        if ((aux_sgmt_eoi_r = '1' and aux_sgmt_stype_r = ST_TAG) 
                            or (aux_sgmt_eoi_r = '1' and aux_instr_decrypt_r = '1' and aux_sgmt_tag_passed = '1'))
                        then
                            n_ostate  <= S_READ_INSTR;
                        else
                            n_ostate  <= S_WRITE_HDR;
                            fifo_read <= '1';
                        end if;
                    end if;
            end case;
        end process;
    end generate;


end behavior;
