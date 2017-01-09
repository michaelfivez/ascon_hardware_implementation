-------------------------------------------------------------------------------
--! @file       PreProcessor_Datapath.vhd
--! @brief      Datapath for the pre-processor
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

entity PreProcessor_Datapath is
    generic (
        G_W                      : integer := 64;   --! Public data width (bits)
        G_SW                     : integer := 64;   --! Secret data width (bits)
        G_CTR_AD_SIZE            : integer := 64;   --! Maximum size for the counter that keeps track of authenticated data
        G_CTR_D_SIZE             : integer := 64;   --! Maximum size for the counter that keeps track of data
        G_DBLK_SIZE              : integer := 128;  --! Block size (bits)
        G_KEY_SIZE               : integer := 128;  --! Key size (bits)
        G_KEYAK                  : integer := 0;    --! Special input mode, used only for Keyak with G_W = 128 and G_DBLK_SIZE = 1344
        G_NPUB_DISABLE           : integer := 0;    --! Disable Npub related port(s)
        G_NPUB_SIZE              : integer := 128;  --! Npub width (bits)
        G_NSEC_ENABLE            : integer := 0;    --! Enable nsec port
        G_NSEC_SIZE              : integer := 128;  --! Nsec width (bits)
        G_LOADLEN_ENABLE         : integer := 0;    --! Enable load length section
        G_PAD                    : integer := 0;    --! Enable padding
        G_PAD_STYLE              : integer := 1;    --! Padding mode 0 = *10...,  1 = ICEPOLE's padding
        G_RDKEY_ENABLE           : integer := 0;    --! Enable rdkey port (also disables key port)
        G_RDKEY_SIZE             : integer := 128;  --! Roundkey size (bits)
        G_TAG_SIZE               : integer := 128   --! Tag size (bits)
    );
    port (
        --! =================
        --! External Signals
        --! =================
        --! Global signals
        clk              : in  std_logic;
        rst              : in  std_logic;
        pdi              : in  std_logic_vector(G_W                        -1 downto 0);    --! Public data
        sdi              : in  std_logic_vector(G_SW                       -1 downto 0);    --! Secret data

        --! =================
        --! Crypto Core Signals
        --! =================
        key              : out std_logic_vector(G_KEY_SIZE                 -1 downto 0);    --! Key data
        rdkey            : out std_logic_vector(G_RDKEY_SIZE               -1 downto 0);    --! Round key data
        bdi              : out std_logic_vector(G_DBLK_SIZE                -1 downto 0);    --! Block data
        npub             : out std_logic_vector(G_NPUB_SIZE                -1 downto 0);    --! Npub data
        nsec             : out std_logic_vector(G_NSEC_SIZE                -1 downto 0);    --! Nsec data
        exp_tag          : out std_logic_vector(G_TAG_SIZE                 -1 downto 0);    --! Expected tag data
        bdi_valid_bytes  : out std_logic_vector(G_DBLK_SIZE/8              -1 downto 0);
        bdi_pad_loc      : out std_logic_vector(G_DBLK_SIZE/8              -1 downto 0);
        len_a            : out std_logic_vector(G_CTR_AD_SIZE              -1 downto 0);    --! Len of authenticated data in bytes (used for some algorithm)
        len_d            : out std_logic_vector(G_CTR_D_SIZE               -1 downto 0);    --! Len of data in bytes (used for some algorithm)

        --! =================
        --! Internal Signals
        --! =================
        --! Control signals
        key_updated      : in  std_logic;                                                   --! (if G_DBLK_SIZE mod G_W > 0) Key updated signal (used only for situation when key is stored within input processor)
        pad_shift        : in  std_logic_vector(log2_ceil(G_W/8)           -1 downto 0);
        en_data          : in  std_logic;                                                   --! Shift data SIPO
        en_npub          : in  std_logic;                                                   --! Shift Npub SIPO
        en_nsec          : in  std_logic;                                                   --! Shift Nsec SIPO
        en_key           : in  std_logic;                                                   --! Shift key SIPO
        en_rdkey         : in  std_logic;                                                   --! Shift round key SIPO
        en_exp_tag       : in  std_logic;                                                   --! Shift expected tag SIPO
        sel_blank_pdi    : in  std_logic;                                                   --! Select input data as blank (for filling in the remaining data within a block)
        clr_len          : in  std_logic;                                                   --! Clear stored length (len_a and len_d)
        en_len_a_r       : in  std_logic;                                                   --! Add authenticated data counter
        en_len_d_r       : in  std_logic;                                                   --! Add data counter
        en_len_last_r    : in  std_logic;                                                   --! Special signal for en_len_*_r
        en_len_a         : in  std_logic;                                                   --! Add authenticated data counter (instant)
        en_len_d         : in  std_logic;                                                   --! Add data counter (no)
        size_dword       : in  std_logic_vector(log2_ceil(G_W/8)              downto 0);    --! Size of data word
        en_last_word     : in  std_logic;                                                   --! Last word in a block
        pad_eot          : in  std_logic;                                                   --! Padding is EOT
        pad_eoi          : in  std_logic;                                                   --! Padding is EOI
        pad_type_ad      : in  std_logic;                                                   --! Padding is AD
        pad_enable       : in  std_logic;                                                   --! Enable padding signal (indicates that the current word requires padding)
        en_pad_loc       : in  std_logic;                                                   --! Save the padding location into a register

        sel_input        : in  std_logic_vector(3                          -1 downto 0)     --! (if G_DBLK_SIZE mod G_W > 0) Select input for m
    );
end PreProcessor_Datapath;

architecture dataflow of PreProcessor_Datapath is

    --! Constants declaration
    constant LOG2_W         :       integer := log2_ceil(G_W/8);                            --! LOG_2(G_W)
    constant LOG2_SW        :       integer := log2_ceil(G_SW/8);                           --! LOG_2(G_SW)
    constant REG_NPUB_WIDTH :       integer := (((G_NPUB_SIZE-1)/G_W)+1)*G_W;               --! Calculate the width of Npub register
    constant CNTR_WIDTH     :       integer := get_cntr_width(G_W);                         --! Calculate the length of p_size register
    constant LEN_A_WIDTH    :       integer := maximum(CNTR_WIDTH, G_CTR_AD_SIZE);
    constant LEN_D_WIDTH    :       integer := maximum(CNTR_WIDTH, G_CTR_D_SIZE);


    constant CNT_DATA_WORDS :       integer := (G_DBLK_SIZE+(G_W-1))/G_W;                   --! Calculate the number of words required for data (rounded up)
    constant CNT_TAG_WORDS  :       integer := (G_DBLK_SIZE+(G_W-1))/G_W;                   --! Calculate the number of words required for tag  (rounded up)
    constant BSHIFT_INPUT   :       std_logic_vector(G_W/8              -1 downto 0) := std_logic_vector(to_unsigned(1,G_W/8));
    constant OWORD_BYTES    :       std_logic_vector(G_DBLK_SIZE/8      -1 downto 0) := (others => '1');  --! The number of bytes in a word in ones.
    constant ZWORD_BYTES    :       std_logic_vector(G_DBLK_SIZE/8      -1 downto 0) := (others => '0');  --! The number of bytes in a word in zeros.

    function reverse_bit(aa: std_logic_vector) return std_logic_vector is
        variable bb : std_logic_vector(aa'high downto aa'low);
    begin
        for i in aa'high downto aa'low loop
            bb(i) := aa(aa'high-i);
        end loop;
        return bb;
    end function reverse_bit;

    type lookup_type is array (0 to ((G_W/8)*2-1)) of std_logic_vector(G_W/8-1 downto 0);

    function getVbytesLookup(size: integer) return lookup_type is
        variable ret : lookup_type;
    begin
        for i in 0 to ((size/8)*2-1) loop
            if (i >= (size/8)) then
                ret(i) := (others => '1');
            elsif (i = 0) then
                ret(i) := (others => '0');
            else
                ret(i)(size/8-1   downto size/8-i) := (others => '1');
                ret(i)(size/8-i-1 downto 0)        := (others => '0');
            end if;
        end loop;
        return ret;
    end function getVbytesLookup;
    constant VBYTES_LOOKUP : lookup_type := getVbytesLookup(G_W);

    --! ==================
    --! Note: Current unused (keep this portion for later consideration)
    function getPlocLookup(size: integer) return lookup_type is
        variable ret : lookup_type;
    begin
        for i in 0 to ((size/8)*2-1) loop
            if (i >= (size/8)) then
                ret(i) := (others => '0');
            else
                ret(i) := (i => '1', others => '0');
            end if;
        end loop;
        return ret;
    end function getPlocLookup;
    constant PLOC_LOOKUP   : lookup_type := getPlocLookup(G_W);
    --! End of note
    --! ==================


    --! Key related signals and registers
    signal reg_key          :       std_logic_vector(G_KEY_SIZE                 -1 downto 0);
    signal reg_rdkey        :       std_logic_vector(G_RDKEY_SIZE               -1 downto 0);

    --! Public data signals and registers
    signal reg_data         :       std_logic_vector(G_DBLK_SIZE                -1 downto 0);       --! Data block register
    signal reg_exp_tag      :       std_logic_vector(G_TAG_SIZE                 -1 downto 0);       --! Tag  register

    signal reg_vbytes       :       std_logic_vector(G_DBLK_SIZE/8              -1 downto 0);       --! Valid bytes register
    signal reg_ploc         :       std_logic_vector(G_DBLK_SIZE/8              -1 downto 0);       --! Pad location register

    signal p_size           :       std_logic_vector(CNTR_WIDTH                 -1 downto 0);       --! Public data segment size
    signal p_zpad_di        :       std_logic_vector(G_W                        -1 downto 0);       --! Internally selected signal for padding
    signal p_1pad_di        :       std_logic_vector(G_W                        -1 downto 0);       --! Internally selected signal for padding
    signal input_data       :       std_logic_vector(G_W                        -1 downto 0);       --! Additional select signal for padding
    signal input_vbytes     :       std_logic_vector(G_W/8                      -1 downto 0);       --! Additional select signal for bytes size
    signal input_ploc       :       std_logic_vector(G_W/8                      -1 downto 0);       --! Additional select signal for bytes size

    --! Data block status register for external modules
    signal len_a_reg        :       std_logic_vector(LEN_A_WIDTH                -1 downto 0);       --! Total authenticated data register
    signal len_d_reg        :       std_logic_vector(LEN_D_WIDTH                -1 downto 0);       --! Total message data register                                                  --! Current block contains no message data (used for authenticated encryption data only mode)

    --! Padding related signals
    signal pad_loc_r        :       std_logic_vector(G_W/8                      -1 downto 0);

    --! Lookups
    signal vbytes           :       std_logic_vector(G_W/8                      -1 downto 0);
    signal ploc             :       std_logic_vector(G_W/8                      -1 downto 0);
begin
    p_zpad_di <= pdi when sel_blank_pdi = '0' else (others => '0');
    vbytes    <= VBYTES_LOOKUP(conv_integer(size_dword));
    ploc      <= PLOC_LOOKUP(conv_integer(size_dword));
    --! Datapath
    procReg:
    process( clk )
    begin
        if rising_edge( clk ) then
            if rst = '1' then
                reg_data            <= (others => '0');
                reg_exp_tag         <= (others => '0');
                len_a_reg           <= (others => '0');
                len_d_reg           <= (others => '0');
                reg_vbytes          <= (others => '0');
            else
                --! === Public data
                --! Data SIPO
                if (en_data = '1') then
                    --! Handle different block size
                    if (G_W >= G_DBLK_SIZE) then
                        reg_data   <= p_1pad_di(G_W-1 downto G_W-G_DBLK_SIZE);
                        reg_vbytes <= vbytes(G_W/8-1 downto G_W/8-G_DBLK_SIZE/8);
                    elsif ((G_DBLK_SIZE MOD G_W) = 0)  then
                        reg_data    <= reg_data(G_DBLK_SIZE-G_W-1 downto 0) & p_1pad_di;
                        reg_vbytes  <= reg_vbytes(G_DBLK_SIZE/8-G_W/8-1 downto 0) & vbytes;
                    elsif ((G_DBLK_SIZE MOD G_W) /= 0) then
                        if (en_last_word = '0') then
                            reg_data  (G_DBLK_SIZE-1   downto ( G_DBLK_SIZE    MOD  G_W))    <= reg_data  (G_DBLK_SIZE-  G_W  -1 downto ( G_DBLK_SIZE    MOD G_W))   & input_data;
                            reg_vbytes(G_DBLK_SIZE/8-1 downto ((G_DBLK_SIZE/8) MOD (G_W/8))) <= reg_vbytes(G_DBLK_SIZE/8-G_W/8-1 downto ((G_DBLK_SIZE/8) MOD (G_W/8))) & input_vbytes;
                        else
                            reg_data   ((G_DBLK_SIZE    mod    G_W )-1 downto 0) <= input_data  (G_W  -1 downto G_W    /2);
                            reg_vbytes(((G_DBLK_SIZE/8) mod (G_W/8))-1 downto 0) <= input_vbytes(G_W/8-1 downto (G_W/8)/2);
                        end if;
                    end if;
                end if;
                --! Tag SIPO
                if (en_exp_tag = '1') then
                    --! Handle different block size
                    if (G_W >= G_TAG_SIZE) then
                        reg_exp_tag <= pdi(G_W-1 downto G_W-G_TAG_SIZE);
                    else
                        reg_exp_tag <= reg_exp_tag(G_TAG_SIZE-G_W-1 downto 0) & pdi;
                    end if;
                end if;

                --! === Secret data
                --! Key SIPO
                if (en_key = '1') then
                    --! Handle different I/O and key size
                    if (G_SW < G_KEY_SIZE) then
                        reg_key <= reg_key(G_KEY_SIZE-G_SW-1 downto 0) & sdi;
                    elsif G_SW = G_KEY_SIZE  then
                        reg_key <= sdi;
                    end if;
                end if;
                --! Round Key SIPO
                if (en_rdkey = '1') then
                    --! Handle different I/O and key size
                    if (G_SW < G_RDKEY_SIZE) then
                        reg_rdkey <= reg_rdkey(G_RDKEY_SIZE-G_SW-1 downto 0) & sdi;
                    elsif G_SW = G_RDKEY_SIZE  then
                        reg_rdkey <= sdi;
                    end if;
                end if;

                --! === Status
                --! Length registers
                if (clr_len = '1') then
                    len_a_reg     <= (others => '0');
                    len_d_reg     <= (others => '0');
                else
                    if (G_LOADLEN_ENABLE = 0) then
                        if (en_len_a = '1') then
                            len_a_reg <= len_a_reg + p_size;
                        end if;
                        if (en_len_d = '1') then
                            len_d_reg <= len_d_reg + p_size;
                        end if;
                    else
                        if (en_len_a_r = '1') then
                            if (G_W >= LEN_A_WIDTH) then
                                len_a_reg <= pdi(LEN_A_WIDTH-1 downto 0);
                            elsif ((LEN_A_WIDTH MOD G_W) = 0)  then
                                len_a_reg <= len_a_reg(LEN_A_WIDTH-G_W-1 downto 0) & pdi;
                            else
                                if (en_len_last_r = '0') then
                                    if (LEN_A_WIDTH/G_W > 1) then
                                        len_a_reg(LEN_A_WIDTH-1 downto (LEN_A_WIDTH MOD G_W)) <= len_a_reg(LEN_A_WIDTH-G_W-1 downto (LEN_A_WIDTH MOD G_W)) & pdi;
                                    else
                                        len_a_reg(LEN_A_WIDTH-1 downto (LEN_A_WIDTH MOD G_W)) <= pdi;
                                    end if;
                                else
                                    len_a_reg((LEN_A_WIDTH MOD G_W)-1 downto 0) <= pdi(G_W-1 downto G_W-(LEN_A_WIDTH MOD G_W));
                                end if;
                            end if;
                        end if;
                        if (en_len_d_r = '1') then
                            if (G_W >= LEN_D_WIDTH) then
                                len_d_reg <= pdi(LEN_D_WIDTH-1 downto 0);
                            elsif ((LEN_D_WIDTH MOD G_W) = 0)  then
                                len_d_reg <= len_d_reg(LEN_D_WIDTH-G_W-1 downto 0) & pdi;
                            else
                                if (en_len_last_r = '0') then
                                    if (LEN_D_WIDTH/G_W > 1) then
                                        len_d_reg(LEN_D_WIDTH-1 downto (LEN_D_WIDTH MOD G_W)) <= len_d_reg(LEN_D_WIDTH-G_W-1 downto (LEN_D_WIDTH MOD G_W)) & pdi;
                                    else
                                        len_d_reg(LEN_D_WIDTH-1 downto (LEN_D_WIDTH MOD G_W)) <= pdi;
                                    end if;
                                else
                                    len_d_reg((LEN_D_WIDTH MOD G_W)-1 downto 0) <= pdi(G_W-1 downto G_W-(LEN_D_WIDTH MOD G_W));
                                end if;
                            end if;
                        end if;
                    end if;
                end if;
            end if;
        end if;
    end process;

    --! Public data size (based on the interface)
    p_size          <= pdi(CNTR_WIDTH               -1 downto 0);

    --! Output
    len_a           <= len_a_reg(G_CTR_AD_SIZE      -1 downto 0);
    len_d           <= len_d_reg(G_CTR_D_SIZE       -1 downto 0);
    bdi             <= reg_data;
    exp_tag         <= reg_exp_tag;
    genKey: if (G_RDKEY_ENABLE = 0) generate
        key         <= reg_key;
    end generate;
    genRdKey: if (G_RDKEY_ENABLE = 1) generate
        rdkey       <= reg_rdkey;
    end generate;
    bdi_valid_bytes <= reg_vbytes;
    bdi_pad_loc     <= reg_ploc;

    genNpub: if (G_NPUB_DISABLE = 0) generate
        signal reg_npub         :       std_logic_vector(REG_NPUB_WIDTH             -1 downto 0);       --! Npub register
    begin
        npub  <= reg_npub(REG_NPUB_WIDTH-1 downto REG_NPUB_WIDTH-G_NPUB_SIZE);

        procReg:
        process( clk )
        begin
            if rising_edge( clk ) then
                if (rst = '1') then
                    reg_npub            <= (others => '0');
                elsif (en_npub = '1') then
                    if (G_W >= G_NPUB_SIZE) then
                        reg_npub      <= pdi(G_W-1 downto G_W-REG_NPUB_WIDTH);
                    else
                        reg_npub      <= reg_npub(REG_NPUB_WIDTH-G_W-1 downto 0) & pdi;
                    end if;
                end if;
            end if;
        end process;
    end generate;

    genNsec: if (G_NSEC_ENABLE = 1) generate
        signal reg_nsec         :       std_logic_vector(G_NSEC_SIZE                -1 downto 0);       --! Nsec register
    begin
        nsec  <= reg_nsec;

        procReg:
        process( clk )
        begin
            if rising_edge( clk ) then
                if (en_nsec = '1') then
                    if (G_W < G_NSEC_SIZE) then
                        reg_nsec    <= reg_nsec(G_NSEC_SIZE-G_W-1 downto 0) & pdi;
                    else
                        reg_nsec    <= pdi(G_W-1 downto G_W-G_NSEC_SIZE);
                    end if;
                end if;
            end if;
        end process;
    end generate;



    --! ============ Special mode ===========
    genPartial: if ((G_DBLK_SIZE mod G_W) > 0) generate
        constant ZEROS      : std_logic_vector(G_W-1 downto 0) := (others => '0');
        signal padded_reg   : std_logic_vector(G_W/2-1 downto 0);
        signal dbytes_reg   : std_logic_vector((G_W/8)/2-1 downto 0);
    begin
        process(clk)
        begin
            if rising_edge(clk) then
                if (en_data = '1' and sel_blank_pdi = '0') then
                    padded_reg <= p_1pad_di(G_W/2-1 downto 0);
                    dbytes_reg <= vbytes((G_W/8)/2-1 downto 0);
                end if;
            end if;
        end process;

        genKeyak0: if G_KEYAK = 0 generate
            with sel_input(2 downto 0) select
            input_data <= p_1pad_di                                                         when "000",
                          p_1pad_di(G_W-1 downto G_W-G_W/2) & ZEROS(G_W-1 downto G_W-G_W/2) when "001",
                          padded_reg & p_1pad_di(G_W-1 downto G_W-G_W/2)                    when "010",
                          padded_reg & ZEROS(G_W-1 downto G_W-G_W/2)                        when "011",
                          (others => '0')                                                   when others;
            with sel_input(2 downto 0) select
            input_vbytes      <= vbytes                                                                     when "000",
                          vbytes(G_W/8-1 downto G_W/8-(G_W/8)/2) & ZEROS(G_W/8-1 downto G_W/8-(G_W/8)/2)    when "001",
                          dbytes_reg & vbytes(G_W/8-1 downto G_W/8-(G_W/8)/2)                               when "010",
                          dbytes_reg & ZEROS(G_W/8-1 downto G_W/8-(G_W/8)/2)                                when "011",
                          (others => '0')                                                                   when others;
        end generate;

        --! Special loading for Keyak
        genKeyak1: if (G_KEYAK = 1 and G_W = 128 and G_DBLK_SIZE = 1344) generate
            signal key_r : std_logic_vector(G_KEY_SIZE-1 downto 0);
        begin
            pKey: process(clk)
            begin
                if rising_edge(clk) then
                    if (key_updated = '1') then
                        key_r <= reg_key;
                    end if;
                end if;
            end process;

            with sel_input(2 downto 0) select
            input_data <= p_1pad_di                                                         when "000",
                          p_1pad_di(G_W-1 downto G_W-G_W/2) & ZEROS(G_W-1 downto G_W-G_W/2) when "001",
                          padded_reg & p_1pad_di(G_W-1 downto G_W-G_W/2)                    when "010",
                          padded_reg & ZEROS(G_W-1 downto G_W-G_W/2)                        when "011",
                          x"1E" & key_r(G_KEY_SIZE-1 downto 8)                              when "100",
                          key_r(7 downto 0) & x"01" & x"000000000000000000000000" & x"0100" when "101",
                          (others => '0')                                                   when others;
            with sel_input(2 downto 0) select
            input_vbytes      <= vbytes                                                                     when "000",
                          vbytes(G_W/8-1 downto G_W/8-(G_W/8)/2) & ZEROS(G_W/8-1 downto G_W/8-(G_W/8)/2)    when "001",
                          dbytes_reg & vbytes(G_W/8-1 downto G_W/8-(G_W/8)/2)                               when "010",
                          dbytes_reg & ZEROS(G_W/8-1 downto G_W/8-(G_W/8)/2)                                when "011",
                          (others => '1')                                       when "100",
                          (others => '1')                                       when "101",
                          (others => '0')                                       when others;
        end generate;
    end generate;

    --! ============ Padding related logic =================
    --! No padding unit
    genPad0: if G_PAD = 0 generate
    begin
        p_1pad_di   <= p_zpad_di;
    end generate;

    --! With padding unit
    genPad1: if G_PAD = 1 generate
        signal pad_loc_s : std_logic_vector(G_W/8       -1 downto 0);
        signal ploc_reg  : std_logic_vector((G_W/8)/2   -1 downto 0);
    begin
        --! No actual padding is performed. However, padding location is produced. Used this mode if bdi_pad_loc signal is required)
        genPadMode0:
        if G_PAD_STYLE = 0 generate
            p_1pad_di <= p_zpad_di;
        end generate;
        --! Pad 10*
        genPadMode1:
        if G_PAD_STYLE = 1 generate
            genLoop:
            for i in 0 to G_W/8-1 generate
                p_1pad_di(G_W-i*8-1)                  <= '1' when (pad_enable = '1' and pad_loc_r(i) = '1' ) else p_zpad_di(G_W-i*8-1);
                p_1pad_di(G_W-i*8-2 downto G_W-i*8-8) <= p_zpad_di(G_W-i*8-2 downto G_W-i*8-8);
            end generate;
        end generate;
        --! Padding mode for ICEPOLE
        genPadMode2:
        if G_PAD_STYLE = 2 generate
            genLoop:
            for i in 0 to G_W/8-1 generate
                p_1pad_di(G_W-i*8-1 downto G_W-i*8-6) <= p_zpad_di(G_W-i*8-1 downto G_W-i*8-6);
                p_1pad_di(G_W-i*8-7) <= '1' when (pad_enable = '1' and pad_loc_r(i) = '1' ) else p_zpad_di(G_W-i*8-7);
                p_1pad_di(G_W-i*8-8) <= '1' when (pad_enable = '1' and pad_loc_r(i) = '1' and ((pad_eot = '1' and pad_type_ad = '1') or (pad_eot = '0' and pad_type_ad = '0'))) else p_zpad_di(G_W-i*8-8);
            end generate;
        end generate;
        --! Padding mode for Keyak
        genPadMode3:
        if G_PAD_STYLE = 3 generate
            genLoop:
            for i in 0 to G_W/8-1 generate
                p_1pad_di(G_W-i*8-1) <= p_zpad_di(G_W-i*8-1);
                p_1pad_di(G_W-i*8-2) <= p_zpad_di(G_W-i*8-2);
                p_1pad_di(G_W-i*8-3) <= p_zpad_di(G_W-i*8-3);
                p_1pad_di(G_W-i*8-4) <= p_zpad_di(G_W-i*8-4);
                p_1pad_di(G_W-i*8-5) <= p_zpad_di(G_W-i*8-5);
                p_1pad_di(G_W-i*8-6) <= '1' when (pad_enable = '1' and pad_loc_r(i) = '1') else p_zpad_di(G_W-i*8-6);
                p_1pad_di(G_W-i*8-7) <= '1' when (pad_enable = '1' and pad_loc_r(i) = '1' and ((pad_type_ad = '1' and pad_eoi = '0' and pad_eot = '1') or (pad_type_ad = '0' and pad_eot = '0'))) else p_zpad_di(G_W-i*8-7);
                p_1pad_di(G_W-i*8-8) <= '1' when (pad_enable = '1' and pad_loc_r(i) = '1' and (pad_type_ad = '0' or (pad_eoi = '1' and pad_type_ad = '1'))) else p_zpad_di(G_W-i*8-8);
            end generate;
        end generate;

        procReg: process(clk)
        begin
            if rising_edge(clk) then
                if en_pad_loc = '1' then
                    pad_loc_r <= pad_loc_s;
                end if;

                if G_W >= G_DBLK_SIZE then
                    if (en_data = '1') then
                        if (pad_enable = '1') then
                            reg_ploc   <= reverse_bit(pad_loc_r);
                        else
                            reg_ploc   <= (others => '0');
                        end if;
                    end if;
                elsif (G_DBLK_SIZE MOD G_W) = 0 then
                    if (en_data = '1') then
                        if (pad_enable = '1') then
                            reg_ploc   <= reg_ploc(G_DBLK_SIZE/8-G_W/8-1 downto 0) & reverse_bit(pad_loc_s);
                        else
                            reg_ploc   <= reg_ploc(G_DBLK_SIZE/8-G_W/8-1 downto 0) & ZWORD_BYTES(G_W/8-1 downto 0);
                        end if;
                    end if;
                elsif (G_DBLK_SIZE MOD G_W) /= 0 then
                    if (rst = '1') then
                        reg_ploc <= (others => '0');
                    elsif (en_data = '1') then
                        ploc_reg <= pad_loc_s(((G_W/8)-1) downto ((G_W/8)/2));
                        if (en_last_word = '0') then
                            if (pad_enable = '1') then
                                reg_ploc(G_DBLK_SIZE/8-1 downto ((G_DBLK_SIZE/8) MOD (G_W/8))) <= reg_ploc(G_DBLK_SIZE/8-G_W/8-1 downto ((G_DBLK_SIZE/8) MOD (G_W/8))) & input_ploc;
                            else
                                reg_ploc(G_DBLK_SIZE/8-1 downto ((G_DBLK_SIZE/8) MOD (G_W/8))) <= reg_ploc(G_DBLK_SIZE/8-G_W/8-1 downto ((G_DBLK_SIZE/8) MOD (G_W/8))) & ZWORD_BYTES(G_W/8-1 downto 0);
                            end if;
                        else
                            if (pad_enable = '1') then
                                reg_ploc(((G_DBLK_SIZE/8) mod (G_W/8))-1 downto 0) <= input_ploc(G_W/8-1 downto (G_W/8)/2);
                            else
                                reg_ploc(((G_DBLK_SIZE/8) mod (G_W/8))-1 downto 0) <= (others => '0');
                            end if;
                        end if;
                    end if;
                end if;
            end if;
        end process;

        gKeyak0:
        if ((G_KEYAK = 0) and ((G_DBLK_SIZE MOD G_W) /= 0)) generate
            with sel_input(2 downto 0) select
            input_ploc   <= reverse_bit(pad_loc_s)                                                                          when "000",
                            reverse_bit(pad_loc_s)(G_W/8-1 downto (G_W/8)/2) & ZWORD_BYTES(G_W/8-1 downto G_W/8-(G_W/8)/2)  when "001",
                            reverse_bit(ploc_reg) & reverse_bit(pad_loc_s((G_W/8)/2-1 downto 0))                            when "010",
                            reverse_bit(ploc_reg) & ZWORD_BYTES(G_W/8-1 downto G_W/8-(G_W/8)/2)                             when "011",
                            (others => '0')                                                                                 when others;
        end generate;
        gKeyak1:
        if (G_KEYAK = 1) generate
            with sel_input(2 downto 0) select
            input_ploc   <= reverse_bit(pad_loc_s)                                                                          when "000",
                            reverse_bit(pad_loc_s)(G_W/8-1 downto (G_W/8)/2) & ZWORD_BYTES(G_W/8-1 downto G_W/8-(G_W/8)/2)  when "001",
                            reverse_bit(ploc_reg) & reverse_bit(pad_loc_s((G_W/8)/2-1 downto 0))                            when "010",
                            reverse_bit(ploc_reg) & ZWORD_BYTES(G_W/8-1 downto G_W/8-(G_W/8)/2)                             when "011",
                            (others => '0')                                                                                 when others;
            -- with sel_input(2 downto 0) select
            -- input_ploc   <= reverse_bit(pad_loc_s)                                               when "000",
                            -- reverse_bit(ploc_reg) & reverse_bit(pad_loc_s((G_W/8)/2-1 downto 0)) when "001",
                            -- reverse_bit(ploc_reg) & ZWORD_BYTES(G_W/8-1 downto G_W/8-(G_W/8)/2)  when "010",
                            -- (others => '0')                                                      when others;
        end generate;

        --! Calculate the padding locatin
        uBarrelShifter:
        entity work.bshift(struct)
        generic map (G_W => G_W/8, G_LOG2_W => LOG2_W, G_LEFT => 1, G_ROTATE => 0)
        port map (ii => BSHIFT_INPUT, rtr => pad_shift, oo => pad_loc_s);
    end generate;


end dataflow;

