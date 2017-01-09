-------------------------------------------------------------------------------
--! @file       PreProcessor_Control.vhd
--! @brief      Control unit for the pre-processor
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

entity PreProcessor_Control is
    generic (
        G_W                      : integer := 32;   --! Public data width (bits)
        G_SW                     : integer := 32;   --! Secret data width (bits)
        G_CIPHERTEXT_MODE        : integer := 0;    --! Ciphertext mode
        G_PLAINTEXT_MODE         : integer := 0;    --! Plaintext Mode
        G_ABLK_SIZE              : integer := 128;  --! Authenticated Data Block size (bits)
        G_DBLK_SIZE              : integer := 128;  --! Data Block size (bits)
        G_BS_BYTES               : integer := 4;    --! The number of bits required to hold block size expressed in bytes = log2_ceil(block_size/8)
        G_KEY_SIZE               : integer := 128;  --! Key size (bits)
        G_NPUB_DISABLE           : integer := 0;    --! Disable Npub related port(s)
        G_NPUB_SIZE              : integer := 128;  --! Npub width (bits)
        G_NSEC_ENABLE            : integer := 0;    --! Enable NSEC port
        G_NSEC_SIZE              : integer := 128;  --! NSEC width (bits)
        G_RDKEY_ENABLE           : integer := 0;    --! Enable rdkey port (also disables key port)
        G_RDKEY_SIZE             : integer := 128;  --! Roundkey size (bits)
        G_REVERSE_DBLK           : integer := 0;    --! Reverse block order (for message only)
        G_LOADLEN_ENABLE         : integer := 0;    --! Enable load length section
        G_CTR_AD_SIZE            : integer := 16;   --! Segment len size
        G_CTR_D_SIZE             : integer := 16;   --! Segment len size
        G_PAD                    : integer := 1;    --! Enable padding
        G_PAD_AD                 : integer := 1;    --! (G_PAD's sub option) Enable AD Padding
        G_PAD_D                  : integer := 1;    --! (G_PAD's sub option) Enable Data padding
        G_TAG_SIZE               : integer := 128;  --! Tag size (bits)
        G_KEYAK                  : integer := 0     --! Special Keyak only mode
    );
    port (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk                 : in  std_logic;
        rst                 : in  std_logic;

        --! Public signals
        pdi                 : in  std_logic_vector(G_W                        -1 downto 0);
        pdi_valid           : in  std_logic;
        pdi_ready           : out std_logic;

        --! Secret signals
        sdi                 : in  std_logic_vector(G_SW                       -1 downto 0);
        sdi_valid           : in  std_logic;
        sdi_ready            : out std_logic;

        error               : out std_logic;

        --! =================
        --! Crypto Core Signals
        --! =================
        --! control signals
        key_ready           : out std_logic;                                                      --! Indicates that the key is ready
        key_needs_update    : out std_logic;                                                      --! Indicates that the key needs update and should be acknowledge by the core via key_updated signal
        key_updated         : in  std_logic;                                                      --! Key has been updated
        rdkey_ready         : out std_logic;                                                      --! Round key ready
        rdkey_read          : in  std_logic;                                                      --! Round key read
        npub_ready          : out std_logic;                                                      --! Npub ready
        npub_read           : in  std_logic;                                                      --! Npub read
        nsec_ready          : out std_logic;                                                      --! Nsec ready
        nsec_read           : in  std_logic;                                                      --! Nsec read
        bdi_ready           : out std_logic;                                                      --! Block ready
        bdi_proc            : out std_logic;                                                      --! Block processing
        bdi_ad              : out std_logic;                                                      --! Input block is an authenticated data
        bdi_nsec            : out std_logic;                                                      --! Input block is a secret message number
        bdi_decrypt         : out std_logic;                                                      --! Decryption operation
        bdi_pad             : out std_logic;                                                      --! Last block of segment type contain padding
        bdi_eot             : out std_logic;                                                      --! Last block of segment type (end-of-type)
        bdi_eoi             : out std_logic;                                                      --! Last block of message (end-of-input)
        bdi_nodata          : out std_logic;                                                      --! Control signal indicating that there's no plain-text or authenticated data. The unit should generate a tag right away.
        bdi_read            : in  std_logic;                                                      --! Handshake signal indicating that the data block has been read
        bdi_size            : out std_logic_vector(G_BS_BYTES                 -1 downto 0);       --! Block size signal. Note: 0 = Full block.
        exp_tag_ready       : out std_logic;                                                      --! Expected tag is ready
        msg_auth_done       : in  std_logic;                                                      --! Tag comparison completion handshake

        bypass_fifo_full    : in  std_logic;                                                      --! An input signal indicating that the bypass FIFO is full
        bypass_fifo_wr      : out std_logic;                                                      --! An output signal for writing data to bypass FIFO

        --! =================
        --! Internal Signals
        --! =================
        pad_shift           : out std_logic_vector(log2_ceil(G_W/8)           -1 downto 0);
        en_data             : out std_logic;                                                      --! Shift data SIPO
        en_npub             : out std_logic;                                                      --! Shift Npub SIPO
        en_nsec             : out std_logic;                                                      --! Shift Nsec SIPO
        en_key              : out std_logic;                                                      --! Shift Key SIPO
        en_rdkey            : out std_logic;                                                      --! Shift Round Key SIPO
        sel_blank_pdi       : out std_logic;                                                      --! Select input data as blank (for filling in the remaining data within a block)
        clr_len             : out std_logic;                                                      --! Clear stored length (len_a and len_d)
        en_len_a_r          : out std_logic;                                                      --! Add authenticated data counter
        en_len_d_r          : out std_logic;                                                      --! Add data counter
        en_len_last_r       : out std_logic;                                                      --! Special signal for en_len_*_r
        en_len_a            : out std_logic;                                                      --! Add authenticated data counter (instant)
        en_len_d            : out std_logic;                                                      --! Add data counter (instant)
        en_exp_tag          : out std_logic;                                                      --! Shift TAG SIPO
        size_dword          : out std_logic_vector(log2_ceil(G_W/8)              downto 0);       --! Size of data word
        en_last_word        : out std_logic;                                                      --! Last word of a block
        --! Pad related control
        pad_eot             : out std_logic;                                                      --! Padding is EOT
        pad_eoi             : out std_logic;                                                      --! Padding is EOI
        pad_type_ad         : out std_logic;                                                      --! Padding is AD
        pad_enable          : out std_logic;                                                      --! Enable padding signal (indicates that the current word requires padding)
        en_pad_loc          : out std_logic;                                                      --! Save the padding location into a register
        --! Supplemental control
        key_updated_int     : out std_logic;                                                      --! Only used for Keyak
        sel_input           : out std_logic_vector(2 downto 0)                                    --! Sel input (used when (G_DBLK_SIZE mod G_W) > 0)
    );
end PreProcessor_Control;

architecture behavior of PreProcessor_Control is
    function getSwCount return integer is
        variable maxval : integer := 0;
    begin
        if (G_NSEC_ENABLE = 1) then
            maxval := G_NSEC_SIZE;
        end if;
        if (G_RDKEY_ENABLE = 1) then
            maxval := maximum(maxval, G_RDKEY_SIZE);
        else
            maxval := maximum(maxval, G_KEY_SIZE);
        end if;
        return log2_ceil(maxval/G_SW);
    end function;

    --! Constants declaration
    constant PARTIAL_LOAD           : integer                                          := isNotDivisible(G_DBLK_SIZE, G_W);
    constant LOG2_W                 : integer                                          := log2_ceil(G_W/8);                                    --! LOG_2(G_W)
    constant LOG2_SWORDS            : integer                                          := getSwCount; --! Expected key words
    constant REGIV_WIDTH            : integer                                          := get_width(G_NPUB_SIZE, G_W);                         --! Calculate the width of Npub register
    constant CNTR_WIDTH             : integer                                          := get_cntr_width(G_W);                                 --! Calculate the length of p_size register
    constant CNT_NPUB_WORDS         : integer                                          := get_words(G_NPUB_SIZE, G_W);                         --! Calculate the number of words required for Npub
    constant CNT_AD_WORDS           : integer                                          := (G_ABLK_SIZE+(G_W-1))/G_W;                           --! Calculate the number of words required for data (rounded up)
    constant CNT_DATA_WORDS         : integer                                          := (G_DBLK_SIZE+(G_W-1))/G_W;                           --! Calculate the number of words required for data (rounded up)
    constant CNT_TAG_WORDS          : integer                                          := (G_TAG_SIZE+(G_W-1))/G_W;                            --! Calculate the number of words required for tag  (rounded up)
    constant CNT_LOADLEN_A_WORDS    : integer                                          := get_words(G_CTR_AD_SIZE, G_W);
    constant CNT_LOADLEN_D_WORDS    : integer                                          := get_words(G_CTR_D_SIZE, G_W);
    constant BSHIFT_INPUT           : std_logic_vector(G_W/8              -1 downto 0) := std_logic_vector(to_unsigned(1,G_W/8));
    constant WCOUNT_SIZE	        : integer                                          := log2_ceil(maximum(maximum(CNT_NPUB_WORDS, CNT_DATA_WORDS), CNT_TAG_WORDS)+1);
    constant ZEROS                  : std_logic_vector(G_DBLK_SIZE-1 downto 0)         := (OTHERS => '0');
    constant SWSIZE                 : integer                                          := log2_ceil(G_SW/8);
    constant SWREMSIZE              : integer                                          := (G_SW-16)-SWSIZE;

    --! Types declaration
    type pstate_type is (SP_WAIT_INSTR,     SP_READ_INSTR,
                         SP_WAIT_HDR,       SP_READ_HDR,       SP_WAIT_NPUB,    SP_WAIT_NSEC,
                         SP_INIT_KEYAK0,    SP_INIT_KEYAK1,    SP_INIT_KEYAK2,  --! Special state for Keyak
                         SP_LOAD_SPECIAL_AD, SP_WAIT_SPECIAL_AD_READ,           --! Special state for G_PAD_AD > 1
                         SP_LOADLEN,                                            --! Special LOADLEN state
                         SP_WAIT_DATA,      SP_WAIT_DATA_READ, SP_WAIT_MSG_AUTH,
                         SP_ERROR);

    type sstate_type is (SS_WAIT_INSTR,     SS_READ_INSTR,
                         SS_WAIT_HDR,       SS_READ_HDR,
                         SS_WAIT_KEY,       SS_DELAY,
                         SS_WAIT_RDKEY,     SS_WAIT_RDKEY_READ);

    --! State signals
    signal pstate               : pstate_type;
    signal sstate               : sstate_type;

    --! Status controls
    signal set_npub_ready       : std_logic;
    signal set_nsec_ready       : std_logic;
    signal clr_nsec_ready       : std_logic;
    signal set_rdkey_ready      : std_logic;

    --! SDI related signals
    signal set_key_needs_update : std_logic;
    signal set_key_ready        : std_logic;
    signal key_ready_r	        : std_logic;
    signal key_needs_update_r   : std_logic;
    signal nsec_ready_r         : std_logic;
    signal rdkey_ready_r        : std_logic;
    signal key_id_r             : std_logic_vector(8                          -1 downto 0);       --! Key id of the key_ready signal
    signal key_act_id_init_r    : std_logic;                                                      --! Status signal for key_act_id (used only after reset)
    signal key_act_id_r         : std_logic_vector(8                          -1 downto 0);       --! Activated key_id

    signal s_opcode             : std_logic_vector(LEN_OPCODE                 -1 downto 0);       --! Secret data opcode
    signal s_stype              : std_logic_vector(LEN_SMT_HDR                -1 downto 0);       --! Secret data segment type
    signal s_size               : std_logic_vector(G_SW-16                    -1 downto 0);       --! Secret data segment size
    signal swcount              : std_logic_vector(LOG2_SWORDS                -1 downto 0);       --! Secret data words count
    signal swrem                : std_logic_vector(SWREMSIZE                  -1 downto 0);       --! Secret data byte remainder
    signal s_key_id             : std_logic_vector(8                          -1 downto 0);       --! Secret data key id

    --! Public data signals and registers
    signal p_reg_stype          : std_logic_vector(LEN_SMT_HDR                -1 downto 0);       --! Segment type register
    signal pwrem                : std_logic_vector(CNTR_WIDTH                 -1 downto 0);       --! Private data words remaining
    signal wcount               : std_logic_vector(WCOUNT_SIZE                -1 downto 0);       --! Word count

    signal p_opcode             : std_logic_vector(LEN_OPCODE                 -1 downto 0);       --! Opcode
    signal p_stype              : std_logic_vector(LEN_SMT_HDR                -1 downto 0);       --! Segment type
    signal p_eot                : std_logic;                                                      --! Last segment of the specified type flag
    signal p_eoi                : std_logic;                                                      --! Last segment of the message flag
    signal p_id                 : std_logic_vector(LEN_MSG_ID                 -1 downto 0);       --! ID
    signal p_size               : std_logic_vector(CNTR_WIDTH                 -1 downto 0);       --! Public data segment size
    signal p_size_r             : std_logic_vector(CNTR_WIDTH                 -1 downto 0);       --! Public data segment size register
    signal p_key_id             : std_logic_vector(8                          -1 downto 0);       --! Public data key id

    signal remainder            : std_logic_vector(CNTR_WIDTH                 -1 downto 0);
    --!     Data block status register
    signal is_ae_r              : std_logic;                                                      --! Current block is an authenticated encryption block

    --!     Data block status registers for external modules
    signal npub_ready_r         : std_logic;
    signal ad_passed_r          : std_logic;
    signal tag_passed_r         : std_logic;
    signal is_decrypt_r         : std_logic;                                                      --! Current message is a decryption
    signal is_ad_r              : std_logic;                                                      --! Current block is an authenticated data block
    signal is_tag_r             : std_logic;                                                      --! Current segment is a tag
    signal is_nsec_r            : std_logic;                                                      --! Current block is a nsec
    signal is_ready_r           : std_logic;                                                      --! Current block is ready
    signal is_eot_r             : std_logic;                                                      --! Current block is the last of its type in the current segment
    signal is_eoi_r             : std_logic;                                                      --! Current block is the last block of message
    signal is_nodata_r          : std_logic;                                                      --! Current block contains no message data (used for authenticated encryption data only mode)
    signal is_first_blk         : std_logic;
    signal is_init_r            : std_logic;
    
    --!     Padding related signals
    signal pad_done             : std_logic;

    --!     Other status registers
    signal exp_tag_ready_r      : std_logic;        --! Needs a delay
    signal needs_extra_block    : std_logic;
    signal needs_extra_block_ad : std_logic;
    signal is_extra_block       : std_logic;
    signal is_partial_data      : std_logic;
    signal total_words          : std_logic_vector(WCOUNT_SIZE                -1 downto 0);

    --! Error registers
    signal errors               : std_logic_vector(8                          -1 downto 0);         --! Error flag (Used for debugging)
    signal error_pdi            : std_logic_vector(8 downto 1);
    signal error_sdi            : std_logic_vector(8 downto 1);
begin
    --! Datapath
    p_reg:
    process( clk )
    begin
        if rising_edge( clk ) then
            if rst = '1' then
                key_needs_update_r <= '0';
                key_ready_r        <= '0';
                bdi_ready          <= '0';
                if (G_NPUB_DISABLE = 0) then
                    npub_ready_r   <= '0';
                end if;
                if (G_NSEC_ENABLE = 1) then
                    nsec_ready_r   <= '0';
                end if;
                if (G_RDKEY_ENABLE = 1) then
                    rdkey_ready_r  <= '0';
                end if;
                key_act_id_init_r  <= '0';
                key_act_id_r       <= (others => '0');
            else
                if (set_key_needs_update = '1') then
                    key_needs_update_r <= '1';
                elsif (key_updated = '1') then
                    key_needs_update_r <= '0';
                end if;

                if (G_NSEC_ENABLE = 1) then
                    if (set_nsec_ready = '1') then
                        nsec_ready_r <= '1';
                    elsif (nsec_read = '1') then
                        nsec_ready_r <= '0';
                    end if;
                end if;
                if (G_NPUB_DISABLE = 0) then
                    if (set_npub_ready = '1') then
                        npub_ready_r <= '1';
                    elsif (npub_read = '1') then
                        npub_ready_r <= '0';
                    end if;
                end if;
                if (G_RDKEY_ENABLE = 1) then
                    if (set_rdkey_ready = '1') then
                        rdkey_ready_r <= '1';
                    elsif (rdkey_read = '1') then
                        rdkey_ready_r <= '0';
                        if (swrem = 0) then
                            key_act_id_init_r <= '1';
                            key_act_id_r      <= key_id_r;
                        end if;
                    end if;
                else
                    if (set_key_ready = '1') then
                        key_ready_r <= '1';
                    elsif (key_updated = '1') then
                        key_ready_r       <= '0';
                        key_act_id_init_r <= '1';
                        key_act_id_r      <= key_id_r;
                    end if;
                end if;

                exp_tag_ready   <= exp_tag_ready_r;
                bdi_ready       <= is_ready_r and not bdi_read;
            end if;
        end if;
    end process;

    gRdkeyEnable0: if (G_RDKEY_ENABLE = 0) generate
        key_ready       <= key_ready_r;
    end generate;
    gRdkeyEnable1: if (G_RDKEY_ENABLE = 1) generate
        rdkey_ready     <= rdkey_ready_r;
    end generate;
    gNsecEnable1: if (G_NSEC_ENABLE = 1) generate
        nsec_ready      <= nsec_ready_r;
    end generate;
    key_needs_update    <= key_needs_update_r;

    s_key_id            <= sdi(G_SW                   -1 downto G_SW- 8);
    s_stype             <= sdi(G_SW- 8                -1 downto G_SW-12);
    s_opcode            <= sdi(G_SW-12                -1 downto G_SW-16);
    s_size              <= sdi(G_SW-16                -1 downto       0);

    p_stype             <= pdi(G_W - 8                -1 downto G_W -12);
    p_opcode            <= pdi(G_W -12                -1 downto G_W -16);
    p_key_id            <= pdi(G_W -16                -1 downto G_W -24);
    p_size              <= pdi(CNTR_WIDTH             -1 downto       0);

    bdi_ad              <= is_ad_r;
    bdi_nsec            <= is_nsec_r;
    bdi_decrypt         <= is_decrypt_r;
    bdi_pad             <= '0';
    bdi_eot             <= is_eot_r;
    bdi_eoi             <= is_eoi_r;
    bdi_nodata          <= is_nodata_r;
    npub_ready          <= npub_ready_r;

    errors              <= error_pdi or error_sdi;
    error               <= nway_or(errors);

    genPad: if (G_PAD = 1) generate
        -- genPadShiftReverse00: if (G_REVERSE_DBLK = 0 and G_PAD_AD /= 4) generate
            -- en_pad_loc <= '1' when (PARTIAL_LOAD = 0 and pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0') or
                                   -- (PARTIAL_LOAD = 1 and pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0' and wcount /= total_words) or
                                   -- (PARTIAL_LOAD = 1 and pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0' and wcount = total_words and is_partial_data = '0')
                              -- else '0';
        -- end generate;
        genPadShiftReverse0: if (G_REVERSE_DBLK = 0) generate
            en_pad_loc <= '1' when ((PARTIAL_LOAD = 0                                    and pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0') or
                                    (PARTIAL_LOAD = 0 and (G_PAD_AD = 2 or G_PAD_AD = 4) and pstate = SP_LOAD_SPECIAL_AD and wcount = 0) or
                                    (PARTIAL_LOAD = 1                                    and pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0' and wcount /= total_words) or
                                    (PARTIAL_LOAD = 1                                    and pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0' and wcount = total_words and is_partial_data = '0'))
                              else '0';
        end generate;
        genPadShiftReverse1: if (G_REVERSE_DBLK = 1) generate
            en_pad_loc <= '1' when ((pstate = SP_WAIT_DATA and p_eot = '1' and pwrem <= G_W/8 and pad_done = '0' and is_ad_r = '1') or
                                    (pstate = SP_WAIT_DATA and is_tag_r = '0' and is_first_blk = '1' and is_ad_r = '0'))  else '0';
        end generate;
    end generate;

    genPadShiftX: if (G_PAD = 1 and (G_PAD_D < 2 and G_PAD_AD < 2)) generate
        genPadShiftReverse0: if (G_REVERSE_DBLK = 0) generate
            pad_shift       <= p_size_r(log2_ceil(G_W/8)-1 downto 0);
        end generate;
        genPadShiftReverse1: if (G_REVERSE_DBLK = 1) generate
            pad_shift       <= remainder(log2_ceil(G_W/8)-1 downto 0) when (remainder(G_BS_BYTES-1 downto 0) < G_DBLK_SIZE/8) else (others => '0');
        end generate;
    end generate;
    genPadShift2: if (G_PAD = 1 and (G_PAD_D  > 1 or G_PAD_AD  > 1)) generate
        pad_shift       <= p_size_r(log2_ceil(G_W/8)-1 downto 0) when is_extra_block = '0' else (others => '0');
    end generate;

    --! Control for public data
    p_pstate:
    process( clk )
    begin
        if rising_edge( clk ) then
            if rst = '1' then
                pstate                  <= SP_WAIT_INSTR;
                en_data                 <= '0';
                en_npub                 <= '0';
                error_pdi               <= (others => '0');
                bypass_fifo_wr          <= '0';
                p_eot                   <= '0';
                p_eoi                   <= '0';
                p_id                    <= (others => '0');
                bdi_proc                <= '0';
                is_ad_r                 <= '0';
                is_tag_r                <= '0';
                is_nsec_r               <= '0';
                is_ae_r                 <= '0';
                is_decrypt_r            <= '0';
                is_ready_r              <= '0';
                is_eot_r                <= '0';
                is_eoi_r                <= '0';
                is_nodata_r             <= '0';
                sel_blank_pdi           <= '0';
                exp_tag_ready_r         <= '0';
                ad_passed_r             <= '0';
                if (G_PAD = 1) then
                    pad_type_ad             <= '0';
                    pad_eot                 <= '0';
                    pad_eoi                 <= '0';
                end if;
                p_reg_stype             <= (others => '0');
                set_key_needs_update    <= '0';
                if (PARTIAL_LOAD = 1) then
                    is_partial_data <= '0';
                    en_last_word    <= '0';
                    sel_input       <= (others => '0');
                end if;
                if (G_NSEC_ENABLE = 1) then
                    set_nsec_ready  <= '0';
                end if;
                if (G_PAD = 1) then
                    pad_enable      <= '0';
                end if;
                if (G_LOADLEN_ENABLE = 1) then
                    en_len_a_r <= '0';
                    en_len_d_r <= '0';
                    if ((G_CTR_AD_SIZE mod G_W /= 0) or (G_CTR_D_SIZE mod G_W /= 0))  then
                        en_len_last_r <= '0';
                    end if;
                end if;
            else
                en_data         <= '0';
                bypass_fifo_wr  <= '0';
                clr_len         <= '0';
                sel_blank_pdi   <= '0';
                en_exp_tag      <= '0';
                set_key_needs_update    <= '0';
                if (G_PAD = 1) then
                    pad_type_ad             <= '0';
                    pad_eot                 <= '0';
                    pad_eoi                 <= '0';
                end if;
                if (PARTIAL_LOAD = 1) then
                    en_last_word    <= '0';
                    sel_input       <= (others => '0');
                end if;
                if (G_NPUB_DISABLE = 0) then
                    en_npub         <= '0';
                    set_npub_ready  <= '0';
                end if;
                if (G_NSEC_ENABLE = 1) then
                    en_nsec         <= '0';
                    set_nsec_ready  <= '0';
                end if;
                if (G_PAD = 1) then
                    pad_enable      <= '0';
                end if;
                if (G_KEYAK = 1) then
                    key_updated_int <= '0';
                end if;
                if (G_LOADLEN_ENABLE = 1) then
                    en_len_a_r <= '0';
                    en_len_d_r <= '0';
                    if ((G_CTR_AD_SIZE mod G_W /= 0) or (G_CTR_D_SIZE mod G_W /= 0))  then
                        en_len_last_r <= '0';
                    end if;
                end if;

                case pstate is
                    when SP_WAIT_INSTR =>
                        if (pdi_valid = '1' and bypass_fifo_full = '0') then
                            pstate             <= SP_READ_INSTR;
                            bypass_fifo_wr     <= '1';
                        end if;

                        pwrem                  <= (others => '0');
                        p_size_r               <= (others => '0');
                        p_eot                  <= '0';
                        p_eoi                  <= '0';
                        p_id                   <= (others => '0');
                        wcount                 <= (others => '0');
                        is_ad_r                <= '0';
                        is_tag_r               <= '0';
                        is_nsec_r              <= '0';
                        is_ae_r                <= '0';
                        is_decrypt_r           <= '0';
                        is_ready_r             <= '0';
                        clr_len                <= '1';
                        is_nodata_r            <= '0';
                        exp_tag_ready_r        <= '0';
                        bdi_size               <= (others => '0');
                        tag_passed_r           <= '0';

                        if G_REVERSE_DBLK = 1 then
                            is_first_blk       <= '1';
                        end if;
                        if (G_KEYAK = 1) then
                            is_init_r          <= '1';
                        end if;
                        if (G_PAD = 1) then
                            if (G_PAD_AD > 1 or G_PAD_D > 1) then
                                is_extra_block         <= '0';
                                needs_extra_block      <= '0';
                                needs_extra_block_ad   <= '0';
                            end if;
                            if (G_PAD_AD > 1) then
                                ad_passed_r            <= '0';
                            end if;
                        end if;

                    when SP_READ_INSTR =>
                        if  (p_opcode /= OP_AE_ENC)
                            and (p_opcode /= OP_AE_DEC)
                            and (p_opcode /= OP_ACT_KEY)
                            and (p_opcode /= OP_ENC)
                            and (p_opcode /= OP_DEC)
                        then
                            pstate              <= SP_ERROR;
                            error_pdi(1)        <= '1';    --! Unsupported opcode
                        else
                            if (p_opcode = OP_AE_DEC) or (p_opcode = OP_DEC) then
                                is_decrypt_r    <= '1';
                            end if;
                            if (p_opcode = OP_AE_DEC or p_opcode = OP_AE_ENC) then
                                is_ae_r         <= '1';
                            end if;
                            if (p_opcode = OP_ACT_KEY) then
                                pstate                  <= SP_WAIT_INSTR;
                                if (key_act_id_init_r = '0'
                                    or (key_act_id_init_r = '1'
                                        and p_key_id /= key_act_id_r))
                                then
                                    set_key_needs_update    <= '1';
                                end if;
                            else
                                pstate                  <= SP_WAIT_HDR;
                                p_reg_stype             <= p_stype;
                                bdi_proc                <= '1';
                            end if;
                        end if;

                    when SP_WAIT_HDR =>
                        if (pdi_valid = '1' and bypass_fifo_full = '0') then
                            pstate              <= SP_READ_HDR;
                            bypass_fifo_wr      <= '1';
                        end if;
                        --! Pad
                        if G_PAD = 1 then
                            pad_done            <= '0';
                        end if;

                    when SP_READ_HDR =>
                        if (not ((G_LOADLEN_ENABLE = 1 and p_stype = ST_LEN)
                            or (p_stype = ST_NPUB)
                            or (p_stype = ST_AD)
                            or (p_stype = ST_MESSAGE and is_decrypt_r = '0')
                            or (p_stype = ST_CIPHER  and is_decrypt_r = '1')
                            or (p_stype = ST_TAG     and is_decrypt_r = '1')))
                        then
                            pstate       <= SP_ERROR;
                            error_pdi(7) <= '1';                            --! Segment type incompatible with opcode
                        else
                            --! Store segment type
                            if (pdi(G_W-15-1) = '1') then
                                p_reg_stype <= p_stype;
                            end if;
                            --! Determining the type and appropriate sequence of inputs. Uses for debugging as well (not fully implemented).
                            if    (p_stype = ST_NPUB) then
                                if  (p_reg_stype = ST_INIT ) or
                                    (G_LOADLEN_ENABLE = 1 and p_reg_stype = ST_LEN )
                                then
                                    if ( p_size /= G_NPUB_SIZE/8 ) then
                                        pstate          <= SP_ERROR;
                                        error_pdi(4)    <= '1';             --! Unsupported Npub Length
                                    else
                                        pstate          <= SP_WAIT_NPUB;
                                    end if;
                                else
                                    pstate              <= SP_ERROR;
                                    error_pdi(6)        <= '1';             --! Segment out of sequence
                                end if;
                            elsif (p_stype = ST_AD) then
                                if ((G_PLAINTEXT_MODE = 0 and (p_reg_stype = ST_NPUB   or p_reg_stype = ST_AD or (G_NSEC_ENABLE = 1 and (p_reg_stype = ST_NSEC or p_reg_stype = ST_NSEC_CIPH))))
                                    or (G_PLAINTEXT_MODE = 1 and (p_reg_stype = ST_INIT   or p_reg_stype = ST_AD))
                                    or (G_PLAINTEXT_MODE = 2 and (p_reg_stype = ST_INIT   or p_reg_stype = ST_AD))
                                    or (G_PLAINTEXT_MODE = 3 and (p_reg_stype = ST_NPUB   or p_reg_stype = ST_AD or p_reg_stype = ST_MESSAGE or p_reg_stype = ST_CIPHER))
                                    or ((G_CIPHERTEXT_MODE = 2 and G_REVERSE_DBLK = 1) and (p_reg_stype = ST_TAG)))
                                then
                                    if (G_KEYAK = 1 and is_init_r = '1') then
                                        is_init_r       <= '0';
                                        pstate          <= SP_INIT_KEYAK0;
                                    else
                                        pstate          <= SP_WAIT_DATA;
                                    end if;
                                    is_ad_r         <= '1';
                                    is_tag_r        <= '0';
                                    is_nsec_r       <= '0';
                                else
                                    pstate          <= SP_ERROR;
                                    error_pdi(6)    <= '1';                 --! Segment out of sequence
                                end if;


                                if (PARTIAL_LOAD = 1) then
                                    total_words     <= std_logic_vector(to_unsigned(CNT_AD_WORDS-1, WCOUNT_SIZE));
                                    is_partial_data <= '0';
                                end if;

                                if (G_PAD = 1) then
                                    if (G_PAD_AD > 1) then
                                        ad_passed_r             <= '1';
                                    end if;

                                    if ((G_PAD_D = 2 or G_PAD_D = 4) and pdi(G_W-14-1) = '1') then       --! EOI
                                        needs_extra_block       <= '1';
                                    end if;
                                    if ((G_ABLK_SIZE = G_DBLK_SIZE and (G_PAD_AD > 2) and G_PLAINTEXT_MODE < 3) and   --! EOT and Full block
                                            pdi(G_BS_BYTES-1 downto 0) = 0 and pdi(G_W-15-1) = '1')
                                    then
                                        needs_extra_block_ad    <= '1';
                                    end if;
                                end if;
                            elsif (p_stype = ST_MESSAGE or p_stype = ST_CIPHER) then
                                if ((G_PLAINTEXT_MODE = 0 and (p_reg_stype = ST_NPUB   or p_reg_stype = ST_AD or p_reg_stype = ST_MESSAGE or p_reg_stype = ST_CIPHER or (G_NSEC_ENABLE = 1 and (p_reg_stype = ST_NSEC or p_reg_stype = ST_NSEC_CIPH))))
                                    or (G_PLAINTEXT_MODE = 1)
                                    or (G_PLAINTEXT_MODE = 2)
                                    or (G_PLAINTEXT_MODE = 3 and (p_reg_stype = ST_NPUB   or p_reg_stype = ST_AD or p_reg_stype = ST_MESSAGE or p_reg_stype = ST_CIPHER))
                                    or ((G_CIPHERTEXT_MODE = 2 and G_REVERSE_DBLK = 1) and (p_reg_stype = ST_TAG)))
                                then
                                    if (G_PLAINTEXT_MODE < 3 and G_PAD = 1 and (G_PAD_AD = 2 or G_PAD_AD = 4) and ad_passed_r = '0') then
                                        --! Empty AD
                                        pstate          <= SP_LOAD_SPECIAL_AD;
                                        is_ad_r         <= '1';
                                        is_extra_block  <= '1';
                                    else
                                        pstate          <= SP_WAIT_DATA;
                                        is_ad_r         <= '0';
                                    end if;
                                    is_tag_r        <= '0';
                                    is_nsec_r       <= '0';
                                else
                                    pstate          <= SP_ERROR;
                                    error_pdi(6)    <= '1';                 --! Segment out of sequence
                                end if;

                                if (PARTIAL_LOAD = 1) then
                                    total_words     <= std_logic_vector(to_unsigned(CNT_DATA_WORDS-1, WCOUNT_SIZE));
                                    is_partial_data <= '0';
                                end if;

                                --! Calculate if additional block needs to be added (only for Message type)
                                if (G_PAD = 1 and G_PAD_D > 2) then
                                    if (pdi(G_BS_BYTES-1 downto 0) = 0 and (G_CIPHERTEXT_MODE < 2 or is_decrypt_r = '0') and pdi(G_W-14-1) = '1') then
                                        needs_extra_block  <= '1';
                                    else
                                        needs_extra_block  <= '0';
                                    end if;
                                end if;
                            elsif (G_NSEC_ENABLE  = 1 and (p_stype = ST_NSEC or p_stype = ST_NSEC_CIPH)) then
                                pstate          <= SP_WAIT_NSEC;
                            elsif (p_stype = ST_TAG) then
                                tag_passed_r  <= '1';
                                if (is_decrypt_r  = '0') then
                                    pstate          <= SP_ERROR;
                                    error_pdi(6)    <= '1';
                                else
                                    pstate          <= SP_WAIT_DATA;
                                    is_tag_r        <= '1';
                                    if (is_ready_r = '0') then
                                        is_ad_r         <= '0';
                                        is_nsec_r       <= '0';
                                    end if;
                                end if;
                            elsif (G_LOADLEN_ENABLE = 1 and p_stype = ST_LEN) then
                                pstate          <= SP_LOADLEN;
                            else    --! Unsupported segment type
                                pstate          <= SP_ERROR;
                                error_pdi(6)    <= '1';
                            end if;
                            pwrem               <= pdi(CNTR_WIDTH-1 downto 0);
                            p_size_r            <= pdi(CNTR_WIDTH-1 downto 0);
                            p_eot               <= pdi(G_W-15-1);
                            p_eoi               <= pdi(G_W-14-1);
                            p_id                <= pdi(G_W-1    downto G_W-8);
                        end if;

                    when SP_LOADLEN =>
                        if (pdi_valid = '1' and bypass_fifo_full = '0') then
                            bypass_fifo_wr  <= '1';
                            if (wcount <= CNT_LOADLEN_A_WORDS-1) then
                                en_len_a_r <= '1';
                            else
                                en_len_d_r <= '1';
                            end if;
                            if ((G_CTR_AD_SIZE mod G_W /= 0) or (G_CTR_D_SIZE mod G_W /= 0))  then
                                if (wcount = CNT_LOADLEN_A_WORDS-1) or
                                   (wcount = (CNT_LOADLEN_A_WORDS+CNT_LOADLEN_D_WORDS-1))
                                then
                                    en_len_last_r <= '1';
                                end if;
                            end if;
                            if (wcount = (CNT_LOADLEN_A_WORDS+CNT_LOADLEN_D_WORDS-1)) then
                                pstate <= SP_WAIT_HDR;
                                wcount <= (others => '0');
                            else
                                wcount <= wcount + 1;
                            end if;
                        end if;

                    when SP_WAIT_NPUB =>
                        if (pdi_valid = '1' and bypass_fifo_full = '0'
                            and (G_NPUB_DISABLE = 1 or npub_ready_r = '0'))
                        then
                            if (pwrem <= G_W/8) then
                                pwrem               <= (others => '0');
                            else
                                pwrem               <= pwrem - G_W/8;
                            end if;
                            if (G_NPUB_DISABLE = 1) then
                                en_data     <= '1';
                            else
                                en_npub     <= '1';
                            end if;
                            bypass_fifo_wr  <= '1';
                            if (wcount = CNT_NPUB_WORDS-1) then
                                pstate          <= SP_WAIT_HDR;
                                wcount          <= (others => '0');

                                if (G_NPUB_DISABLE = 0) then
                                    set_npub_ready    <= '1';
                                end if;
                            else
                                wcount          <= wcount + 1;
                            end if;
                        end if;

                    when SP_WAIT_NSEC =>
                        if (pdi_valid = '1' and nsec_ready_r = '0') then
                            en_nsec          <= '1';
                            if (G_NSEC_SIZE > G_W) then
                                if (wcount = (G_NSEC_SIZE/G_W)-1) then
                                    pstate          <= SP_WAIT_HDR;
                                    set_nsec_ready  <= '1';
                                else
                                    wcount   <= wcount + 1;
                                end if;
                            else
                                pstate          <= SP_WAIT_HDR;
                                set_nsec_ready  <= '1';
                            end if;
                        end if;

                    when SP_INIT_KEYAK0 =>
                        if (key_needs_update_r = '1' and key_ready_r = '1') then
                            key_updated_int <= '1';
                            pstate          <= SP_INIT_KEYAK1;
                        elsif (key_needs_update_r = '0') then
                            pstate          <= SP_INIT_KEYAK1;
                        end if;

                    when SP_INIT_KEYAK1 =>
                        sel_input <= "100";
                        en_data   <= '1';
                        wcount <= wcount + 1;
                        pstate <= SP_INIT_KEYAK2;

                    when SP_INIT_KEYAK2 =>
                        sel_input <= "101";
                        en_data   <= '1';
                        wcount    <= wcount + 1;
                        pstate    <= SP_WAIT_DATA;

                    when SP_LOAD_SPECIAL_AD =>
                        en_data          <= '1';
                        sel_blank_pdi    <= '1';
                        if (G_PAD = 1 and wcount = 0) then
                            pad_enable      <= '1';
                            pad_done        <= '1';
                            pad_eot         <= p_eot;
                            pad_eoi         <= p_eoi;
                            pad_type_ad     <= is_ad_r;
                        end if;
                        if (wcount = CNT_DATA_WORDS-1) then
                            p_size_r        <= p_size_r - G_DBLK_SIZE/8;
                            size_dword      <= (others => '0');
                            bdi_size        <= (others => '0');
                            wcount          <= (others => '0');
                            is_ready_r      <= '1';
                            is_nodata_r     <= '1';
                            is_eot_r        <= '1';
                            pstate          <= SP_WAIT_SPECIAL_AD_READ;
                        else
                            wcount <= wcount + 1;
                        end if;

                    when SP_WAIT_SPECIAL_AD_READ =>
                        if (bdi_read = '1') then
                            is_ready_r      <= '0';
                            is_eot_r        <= '0';
                            is_eoi_r        <= '0';
                            is_ad_r         <= '0';
                            is_nodata_r     <= '0';
                            is_extra_block  <= '0';
                            pad_done        <= '0';
                            if (p_reg_stype = ST_NPUB) then
                                pstate      <= SP_WAIT_INSTR;
                                bdi_proc    <= '0';
                            elsif (p_reg_stype = ST_AD) then
                                pstate      <= SP_WAIT_HDR;
                            else
                                pstate      <= SP_WAIT_DATA;
                            end if;
                        end if;

                    when SP_WAIT_DATA =>
                        if (((is_ad_r = '1' or (is_nsec_r = '1' and G_NSEC_ENABLE = 1))
                                and bypass_fifo_full = '0' and pdi_valid = '1')
                            or (is_ad_r = '0' and pdi_valid = '1')
                            or (pwrem = 0     and p_eot = '1')
                            or (PARTIAL_LOAD = 1 and is_partial_data = '1'))
                        then
                            --! If remaining data word is 0, pad input block with 0
                            if (pwrem /= 0) then
                                if (is_ad_r = '1' and is_tag_r = '0') then
                                    if (PARTIAL_LOAD = 0) then
                                        bypass_fifo_wr      <= '1';
                                    elsif (PARTIAL_LOAD = 1 and
                                           ((wcount < total_words) or
                                            (wcount = total_words and is_partial_data = '0')))
                                    then
                                        bypass_fifo_wr      <= '1';
                                    end if;
                                end if;
                            else
                                sel_blank_pdi       <= '1';
                            end if;
                            --! Perform padding
                            if (G_PAD = 1) then
                                if (((PARTIAL_LOAD = 0 and p_eot = '1'
                                        and pwrem < G_W/8 and pad_done = '0')
                                    or (PARTIAL_LOAD = 1 and p_eot = '1'
                                        and pwrem < G_W/8 and pad_done = '0'
                                        and (wcount /= total_words or (wcount = total_words and is_partial_data = '0')))
                                    or (G_REVERSE_DBLK = 1 and is_first_blk = '1'
                                        and is_ad_r = '0' and remainder(G_BS_BYTES-1 downto 0) < G_DBLK_SIZE/8
                                        and remainder(G_BS_BYTES-1 downto 0) /= 0 and is_decrypt_r = '1')))
                                then
                                    if ((is_ad_r = '0' and G_PAD_D > 0) or
                                        (is_ad_r = '1' and is_tag_r = '0' and G_PAD_AD > 0) or
                                        (G_PAD_D > 0 and G_PAD_AD > 0))
                                    then
                                        pad_enable      <= '1';
                                        pad_done        <= '1';
                                        pad_eot         <= p_eot;
                                        pad_eoi         <= p_eoi;
                                        pad_type_ad     <= is_ad_r;
                                    end if;
                                end if;
                            end if;

                            if ((PARTIAL_LOAD = 1) and
                                    ((G_ABLK_SIZE = G_DBLK_SIZE and wcount = CNT_DATA_WORDS-1)
                                    or (G_ABLK_SIZE /= G_DBLK_SIZE and wcount = total_words)))
                            then
                                if (is_partial_data = '0') then
                                    if (pwrem <= G_W/8) then
                                        pwrem               <= (others => '0');
                                    else
                                        pwrem               <= pwrem - G_W/8;
                                    end if;
                                end if;
                            else
                                if (G_ABLK_SIZE = G_DBLK_SIZE) then
                                    if (pwrem <= G_W/8) then
                                        pwrem               <= (others => '0');
                                    else
                                        pwrem               <= pwrem - G_W/8;
                                    end if;
                                else
                                    if (wcount < total_words) then
                                        if (pwrem <= G_W/8) then
                                            pwrem               <= (others => '0');
                                        else
                                            pwrem               <= pwrem - G_W/8;
                                        end if;
                                    end if;
                                end if;
                            end if;

                            if (G_REVERSE_DBLK = 0) then
                                if (pwrem <= G_W/8) then
                                    size_dword          <= pwrem(log2_ceil(G_W/8) downto 0);
                                else
                                    size_dword          <= std_logic_vector(to_unsigned(G_W/8,log2_ceil(G_W/8)+1));
                                end if;
                            else
                                --! Special case for PRIMATEs-APE
                                if    (is_ad_r = '1' and pwrem <= G_W/8) then
                                    size_dword          <= pwrem(log2_ceil(G_W/8) downto 0);
                                elsif (is_ad_r = '0' and is_first_blk = '1' and remainder(G_BS_BYTES-1 downto 0) < G_DBLK_SIZE/8 and remainder(G_BS_BYTES-1 downto 0) /= 0) then
                                    size_dword          <= remainder(log2_ceil(G_W/8) downto 0);
                                else
                                    size_dword          <= std_logic_vector(to_unsigned(G_W/8,log2_ceil(G_W/8)+1));
                                end if;
                            end if;

                            if (is_tag_r = '0') then
                                en_data         <= '1';
                                if (wcount = CNT_DATA_WORDS-1) then
                                    --! Handling case when AD_BLOCK /= Data_BLOCK
                                    if (G_ABLK_SIZE /= G_DBLK_SIZE) then
                                        if (is_ad_r = '1') then
                                            p_size_r <= p_size_r - G_ABLK_SIZE/8;
                                        else
                                            p_size_r <= p_size_r - G_DBLK_SIZE/8;
                                        end if;
                                    else
                                        if (G_KEYAK = 0) then
                                            p_size_r <= p_size_r - G_DBLK_SIZE/8;
                                        else
                                            p_size_r <= p_size_r - (G_DBLK_SIZE/8 - 256/8);
                                        end if;
                                    end if;
                                    wcount <= (others => '0');

                                    --! Status signals and state transition
                                    is_ready_r          <= '1';
                                    if (PARTIAL_LOAD = 1) then
                                        en_last_word    <= '1';
                                        if ((pwrem <= (G_W/8)/2) and
                                             (is_partial_data = '0'))
                                        then
                                            --! If it's decrypt and of type message, start loading tag segment
                                            if (is_decrypt_r = '1' and p_eoi = '1') then
                                                pstate      <= SP_WAIT_HDR;
                                            else
                                                pstate      <= SP_WAIT_DATA_READ;
                                            end if;
                                        else
                                            pstate          <= SP_WAIT_DATA_READ;
                                        end if;
                                    else
                                        if ((G_REVERSE_DBLK = 0) or (is_decrypt_r = '0') or (is_ad_r = '1')) then
                                            --! Case when Reverse data block is required
                                            if (pwrem < G_W/8) then
                                                bdi_size        <= p_size_r(G_BS_BYTES-1 downto 0);
                                            else
                                                bdi_size        <= (others => '0');
                                            end if;
                                        else
                                            if (is_first_blk = '1' and is_ad_r = '0') then
                                                if (remainder(G_BS_BYTES-1 downto 0) < G_DBLK_SIZE/8) then
                                                    bdi_size    <= remainder(G_BS_BYTES-1 downto 0);
                                                else
                                                    bdi_size    <= (others => '0');
                                                end if;
                                                is_first_blk <= '0';
                                            else
                                                bdi_size        <= (others => '0');
                                            end if;
                                        end if;
                                        if (pwrem <= G_W/8) then
                                            if (G_PAD = 1 and ((G_PAD_D > 1 and needs_extra_block = '1' and is_ad_r = '0') or (G_PAD_AD > 1 and needs_extra_block_ad = '1'))) then
                                                is_eot_r    <= '0';
                                            else
                                                is_eot_r    <= p_eot;
                                            end if;
                                            --! If it's decrypt and of type message, start loading tag segment
                                            if (is_decrypt_r = '1' and is_ad_r = '0' and p_eot = '1') then
                                                is_eoi_r    <= p_eot;
                                                if ((G_REVERSE_DBLK = 1 and G_CIPHERTEXT_MODE = 2) and p_eoi = '1') then
                                                    pstate      <= SP_WAIT_MSG_AUTH;
                                                elsif (G_PAD = 1 and (G_PAD_D > 2 and needs_extra_block = '1')) then
                                                    pstate      <= SP_WAIT_DATA_READ;
                                                else
                                                    pstate      <= SP_WAIT_HDR;
                                                end if;
                                            else
                                                if (G_PAD = 1 and ((G_PAD_D > 1 and needs_extra_block = '1') or (G_PAD_AD > 1 and needs_extra_block_ad = '1'))) then
                                                    is_eoi_r        <= '0';
                                                else
                                                    is_eoi_r        <= p_eoi;
                                                end if;
                                                pstate      <= SP_WAIT_DATA_READ;
                                            end if;
                                        else
                                            pstate <= SP_WAIT_DATA_READ;
                                        end if;
                                    end if;
                                else
                                    wcount <= wcount + 1;
                                end if;
                                if (PARTIAL_LOAD = 1) then
                                    --! Special case when (G_DBLK_SIZE mod G_W = G_W/2)
                                    if (wcount < total_words) then
                                        if (pwrem <= (G_W/8)/2) then
                                            is_partial_data <= '0';
                                        end if;
                                    elsif (wcount = total_words) then
                                        if ((is_partial_data = '0')
                                            and ((pwrem > ((G_ABLK_SIZE/8) mod (G_W/8)) and is_ad_r = '1')
                                                or (pwrem > ((G_DBLK_SIZE/8) mod (G_W/8)) and is_ad_r = '0')))
                                        then
                                            is_partial_data <= '1';
                                        else
                                            is_partial_data <= '0';
                                        end if;
                                        if (((pwrem < (G_W/8)/2 and is_partial_data = '0')
                                                or (pwrem = 0 and is_partial_data = '1'))
                                            and ((is_ad_r = '1' and p_size_r(G_BS_BYTES-1 downto 0) /= G_ABLK_SIZE/8)
                                                or (is_ad_r = '0' and p_size_r(G_BS_BYTES-1 downto 0) /= G_DBLK_SIZE/8)))
                                        then
                                            bdi_size        <= p_size_r(G_BS_BYTES-1 downto 0);
                                        else
                                            bdi_size        <= (others => '0');
                                        end if;
                                        if  (is_partial_data = '0' and pwrem <= (G_W/8)/2) or
                                            (is_partial_data = '1' and pwrem = 0         )
                                        then
                                            is_eot_r        <= p_eot;
                                            is_eoi_r        <= p_eoi;
                                        else
                                            is_eot_r        <= '0';
                                        end if;
                                    end if;

                                    if (wcount < total_words) then
                                        if (is_partial_data = '0') then
                                            sel_input <= "000"; --! D[HI] & D[LO]
                                        else
                                            if (pwrem = 0) then
                                                sel_input <= "011"; --! D[LO] & 00..
                                            else
                                                sel_input <= "010"; --! D[LO] & D[HI]
                                            end if;
                                        end if;
                                    elsif (wcount = total_words) then
                                        if (is_partial_data = '0') then
                                            sel_input <= "001"; --! D[HI] & 00..
                                        else
                                            sel_input <= "011"; --! D[LO] & 00..
                                        end if;
                                    else
                                        sel_input <= "111"; --! "00..."
                                    end if;
                                end if;
                            else
                                if (bdi_read = '1') then
                                    is_ready_r <= '0';
                                end if;

                                en_exp_tag          <= '1';
                                if (wcount = CNT_TAG_WORDS-1) then
                                    wcount <= (others => '0');
                                    if (p_eoi = '1') then
                                        pstate        <= SP_WAIT_MSG_AUTH;
                                    else
                                        pstate        <= SP_WAIT_HDR;
                                    end if;
                                    exp_tag_ready_r <= '1';
                                else
                                    wcount <= wcount + 1;
                                end if;
                            end if;
                        end if;

                    when SP_WAIT_DATA_READ =>
                        wcount <= (others => '0');
                        if (bdi_read = '1') then
                            is_ready_r      <= '0';
                            is_eot_r        <= '0';
                            is_eoi_r        <= '0';
                            is_nodata_r     <= '0';

                            if (pwrem = 0) then
                                if (G_PAD = 1
                                    and (G_PAD_AD > 1 or G_PAD_D > 1)
                                    and (needs_extra_block = '1' or needs_extra_block_ad = '1')) then
                                    --! Special cases
                                    if (needs_extra_block = '1') then
                                        pstate                  <= SP_WAIT_DATA;
                                        needs_extra_block       <= '0';
                                        is_ad_r                 <= '0';
                                    elsif (needs_extra_block_ad = '1') then
                                        pstate                  <= SP_LOAD_SPECIAL_AD;
                                        needs_extra_block_ad    <= '0';
                                        is_ad_r                 <= '1';
                                    end if;
                                    is_extra_block     <= '1';
                                    is_nodata_r        <= '1';
                                    pad_done           <= '0';
                                elsif (PARTIAL_LOAD = 1 and is_partial_data = '1') then
                                    pstate             <= SP_WAIT_DATA;
                                else
                                    if (G_PAD = 1 and (G_PAD_AD > 1 or G_PAD_D > 1)) then
                                        is_extra_block     <= '0';
                                    end if;
                                    if (p_eoi = '1') then
                                        if (is_decrypt_r = '1') then    --! If AEAD_DECRYPT, there must be a tag segment after last message segment
                                            if (tag_passed_r = '1') then
                                                pstate        <= SP_WAIT_MSG_AUTH;
                                            else
                                                pstate        <= SP_WAIT_HDR;
                                            end if;
                                        else
                                            pstate        <= SP_WAIT_INSTR;
                                            bdi_proc      <= '0';
                                        end if;
                                    else
                                        pstate  <= SP_WAIT_HDR;
                                    end if;
                                end if;
                            else
                                if (G_PAD = 1
                                    and (G_PAD_AD = 2 or G_PAD_AD = 4)
                                    and is_extra_block = '1'
                                    and is_ad_r = '1')
                                then    --! Empty AD
                                    is_ad_r     <= '0';
                                    is_nodata_r <= '0';
                                end if;
                                pstate <= SP_WAIT_DATA;
                            end if;
                        end if;

                    when SP_WAIT_MSG_AUTH =>
                        if (msg_auth_done = '1') then
                            pstate        <= SP_WAIT_INSTR;
                            bdi_proc      <= '0';
                            is_ready_r    <= '0';
                            is_eot_r      <= '0';
                            is_eoi_r      <= '0';
                        elsif (bdi_read = '1') then
                            is_ready_r <= '0';
                        end if;

                    when SP_ERROR =>
                        pstate      <= SP_ERROR;
                end case;
            end if;
        end if;
    end process;
    --! Unregistered control signals (Required for correct timing)
    pdi_ready         <= '1' when pdi_valid = '1' and (
                        (pstate  = SP_WAIT_INSTR and bypass_fifo_full = '0') or
                        (pstate  = SP_WAIT_HDR   and bypass_fifo_full = '0') or
                        (pstate  = SP_WAIT_NPUB  and (npub_ready_r = '0' or G_NPUB_DISABLE = 1) and bypass_fifo_full = '0') or
                        (pstate = SP_WAIT_NSEC   and G_NSEC_ENABLE = 1    and nsec_ready_r = '0') or
                        (pstate = SP_LOADLEN     and G_LOADLEN_ENABLE = 1) or
                        (pstate  = SP_WAIT_DATA  and PARTIAL_LOAD = 0
                            and (((is_ad_r     = '1' or (is_nsec_r = '1' and G_NSEC_ENABLE = 1)) and bypass_fifo_full = '0' and pwrem /= 0)
                                or (is_ad_r     = '0' and pwrem /= 0))) or
                        (pstate  = SP_WAIT_DATA  and PARTIAL_LOAD = 1 and
                            (wcount < total_words or (wcount = total_words and is_partial_data = '0')) and
                            (((is_ad_r     = '1' or (is_nsec_r = '1' and G_NSEC_ENABLE = 1)) and bypass_fifo_full = '0' and pwrem /= 0) or
                             (is_ad_r     = '0' and pwrem /= 0)))
                        ) else '0';
    gLoadLenDisable:
    if (G_LOADLEN_ENABLE /= 1) generate
        en_len_a <= '1' when (pstate = SP_READ_HDR   and p_stype = ST_AD)      else '0';
        en_len_d <= '1' when (pstate = SP_READ_HDR   and (p_stype = ST_MESSAGE or p_stype = ST_CIPHER)) else '0';
    end generate;

    --! Division required for reverse block mode
    gRB:
    if (G_REVERSE_DBLK = 1) generate
        remainder <= std_logic_vector(unsigned(p_size_r) MOD to_unsigned(G_DBLK_SIZE/8, CNTR_WIDTH));
    end generate;

    --! Control for secret data
    p_sstate:
    process( clk )
    begin
        if rising_edge( clk ) then
            if rst = '1' then
                sstate          <= SS_WAIT_INSTR;
                if (G_RDKEY_ENABLE = 1) then
                    set_rdkey_ready <= '0';
                else
                    set_key_ready   <= '0';
                end if;
                error_sdi       <= (others => '0');
            else
                if (G_RDKEY_ENABLE = 1) then
                    en_rdkey        <= '0';
                    set_rdkey_ready <= '0';
                else
                    en_key          <= '0';
                    set_key_ready   <= '0';
                end if;

                case sstate is
                    when SS_WAIT_INSTR =>
                        if (sdi_valid = '1') then
                            sstate          <= SS_READ_INSTR;
                        end if;
                    when SS_READ_INSTR =>
                        if (s_opcode /= OP_LD_KEY and s_opcode /= OP_LD_RKEY) then
                            sstate          <= SS_WAIT_INSTR;
                            error_sdi(1)    <= '1';                     --! Unsupported opcode
                        else
                            sstate          <= SS_WAIT_HDR;
                        end if;
                    when SS_WAIT_HDR =>
                        if (sdi_valid = '1'
                            and ((G_RDKEY_ENABLE = 0 and key_ready_r = '0') or
                                 (G_RDKEY_ENABLE = 1 and rdkey_ready_r = '0')))
                        then
                            sstate  <= SS_READ_HDR;
                        end if;
                    when SS_READ_HDR =>
                        swcount         <= (others => '0');
                        key_id_r        <= s_key_id;
                        if (G_RDKEY_ENABLE = 0 and (s_stype = ST_KEY and s_size = G_KEY_SIZE/8)) then
                            sstate          <= SS_WAIT_KEY;
                        elsif (G_RDKEY_ENABLE = 1 and s_stype = ST_RDKEY) then
                            sstate          <= SS_WAIT_RDKEY;
                            swrem           <= sdi(SWREMSIZE+SWSIZE-1 downto SWSIZE)+nway_or(sdi(SWSIZE-1 downto 0));
                        else
                            error_sdi(7)    <= '1';                 --! Segment error
                            sstate          <= SS_WAIT_INSTR;
                        end if;
                    when SS_WAIT_KEY =>
                        if (sdi_valid = '1') then
                            en_key          <= '1';
                            if (swcount = (G_KEY_SIZE/G_SW)-1) then
                                sstate          <= SS_DELAY;
                                set_key_ready   <= '1';
                            else
                                swcount   <= swcount + 1;
                            end if;
                        end if;
                    when SS_DELAY =>
                        sstate <= SS_WAIT_INSTR;
                    when SS_WAIT_RDKEY =>
                        if (sdi_valid = '1') then
                            en_rdkey  <= '1';
                            swrem     <= swrem - 1;
                            if (swcount = (G_KEY_SIZE/G_SW)-1) then
                                set_rdkey_ready <= '1';
                                sstate          <= SS_WAIT_RDKEY_READ;
                            else
                                swcount   <= swcount + 1;
                            end if;
                        end if;
                    when SS_WAIT_RDKEY_READ =>
                        swcount <= (others => '0');
                        if (rdkey_read = '1') then
                            if (swrem = 0) then
                                sstate <= SS_WAIT_INSTR;
                            else
                                sstate <= SS_WAIT_RDKEY;
                            end if;
                        end if;

                end case;
            end if;
        end if;
    end process;

    sdi_ready <= '1' when sdi_valid = '1' and (
                            (sstate = SS_WAIT_INSTR) or
                            (sstate = SS_WAIT_HDR and ((key_ready_r = '0' and G_RDKEY_ENABLE = 0) or (rdkey_ready_r = '0' and G_RDKEY_ENABLE = 1))) or
                            (sstate = SS_WAIT_KEY) or
                            (sstate = SS_WAIT_RDKEY and rdkey_read = '1')
                            ) else '0';

end behavior;
