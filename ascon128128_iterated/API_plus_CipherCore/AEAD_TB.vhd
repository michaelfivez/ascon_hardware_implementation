-------------------------------------------------------------------------------
--! @file       AEAD_TB.vhd
--! @brief      Testbench for GMU CAESAR project.
--! @project    CAESAR Candidate Evaluation
--! @author     Ekawat (ice) Homsirikamol
--! @copyright  Copyright (c) 2015 Cryptographic Engineering Research Group
--!             ECE Department, George Mason University Fairfax, VA, U.S.A.
--!             All rights Reserved.
--! @version    1.0b1
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is publicly available encryption source code that falls
--!             under the License Exception TSU (Technology and software-
--!             —unrestricted)
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.ALL;
use ieee.numeric_std.all;
use ieee.std_logic_textio.all;
use work.std_logic_1164_additions.all;
use work.AEAD_pkg.all;

library std;
use std.textio.all;

entity AEAD_TB IS
    generic (
        --! Test parameters
        G_STOP_AT_FAULT     : boolean := True;
        G_TEST_MODE         : integer := 0;
        G_TEST_ISTALL       : integer := 10;
        G_TEST_OSTALL       : integer := 10;

        G_LOG2_FIFODEPTH    : integer := 8;
        G_PWIDTH            : integer := 32;
        G_SWIDTH            : integer := 32;
        G_PERIOD            : time    := 10 ns;
        G_FNAME_PDI         : string  := "pdi.txt";
        G_FNAME_SDI         : string  := "sdi.txt";
        G_FNAME_DO          : string  := "do.txt";
        G_FNAME_LOG         : string  := "log.txt";
        G_FNAME_RESULT      : string  := "result.txt"
    );
end AEAD_TB;

architecture behavior of AEAD_TB is
    --! =================== --
    --! SIGNALS DECLARATION --
    --! =================== --

    --! simulation signals (used by ATHENa script, ignore if not used)
    signal simulation_fails     : std_logic := '0';          --! '0' signifies a pass at the end of simulation, '1' is fail
    signal stop_clock           : boolean   := False;        --! '1' signifies a completed simulation, '0' otherwise

    --! error check signal
    signal global_stop          : std_logic := '1';

    --! globals
    signal clk                  : std_logic := '0';
    signal io_clk               : std_logic := '0';
    signal rst                  : std_logic := '0';

    --! do
    signal do_ext               : std_logic_vector(G_PWIDTH-1 downto 0);
    signal do                   : std_logic_vector(G_PWIDTH-1 downto 0);
    signal do_empty             : std_logic;
    signal do_full              : std_logic;
    signal do_read              : std_logic := '0';
    signal do_valid             : std_logic;
    signal do_full_selected     : std_logic;
    signal do_write_selected    : std_logic;
    signal do_ready             : std_logic;

    --! pdi
    signal pdi_ext              : std_logic_vector(G_PWIDTH-1 downto 0) := (others=>'0');
    signal pdi                  : std_logic_vector(G_PWIDTH-1 downto 0);
    signal pdi_empty            : std_logic;
    signal pdi_full             : std_logic;
    signal pdi_ready            : std_logic;
    signal pdi_write            : std_logic := '0';
    signal pdi_read_selected    : std_logic;
    signal pdi_empty_selected   : std_logic;
    signal pdi_valid            : std_logic;
    signal pdi_delayed          : std_logic_vector(G_PWIDTH-1 downto 0);

    --! sdi
    signal sdi_ext              : std_logic_vector(G_SWIDTH-1 downto 0) := (others=>'0');
    signal sdi                  : std_logic_vector(G_SWIDTH-1 downto 0);
    signal sdi_empty            : std_logic;
    signal sdi_full             : std_logic;
    signal sdi_ready            : std_logic;
    signal sdi_write            : std_logic := '0';
    signal sdi_read_selected    : std_logic;
    signal sdi_empty_selected   : std_logic;
    signal sdi_valid            : std_logic;
    signal sdi_delayed          : std_logic_vector(G_SWIDTH-1 downto 0);

    --! Verification signals
    signal stall_pdi_empty      : std_logic := '0';
    signal stall_sdi_empty      : std_logic := '0';
    signal stall_do_full        : std_logic := '0';


    ------------- clock constant ------------------
    constant clk_period         : time := G_PERIOD;
    constant io_clk_period      : time := clk_period;
    ----------- end of clock constant -------------

    ------------- string constant ------------------
    --! constant
    constant cons_ins           : string(1 to 6) := "INS = ";
    constant cons_hdr           : string(1 to 6) := "HDR = ";
    constant cons_dat           : string(1 to 6) := "DAT = ";

    --! Shared constant
    constant cons_eof           : string(1 to 6) := "###EOF";
    ----------- end of string constant -------------

    ------------- debug constant ------------------
    constant debug_input        : boolean := False;
    constant debug_output       : boolean := False;
    ----------- end of clock constant -------------

    -- ================= --
    -- FILES DECLARATION --
    -- ================= --

    --------------- input / output files -------------------
    file pdi_file               : text open read_mode  is G_FNAME_PDI;
    file sdi_file               : text open read_mode  is G_FNAME_SDI;
    file do_file                : text open read_mode  is G_FNAME_DO;

    file log_file               : text open write_mode is G_FNAME_LOG;
    file result_file            : text open write_mode is G_FNAME_RESULT;
    ------------- end of input files --------------------
begin

    genClk: process
    begin
        if (not stop_clock and global_stop = '1') then
            clk <= '1';
            wait for clk_period/2;
            clk <= '0';
            wait for clk_period/2;
        else
            wait;
        end if;
    end process genClk;

    genIOclk: process
    begin
        if ((not stop_clock) and (global_stop = '1')) then
            io_clk <= '1';
            wait for io_clk_period/2;
            io_clk <= '0';
            wait for io_clk_period/2;
        else
            wait;
        end if;
    end process genIOclk;

    --! ============ --
    --! PORT MAPPING --
    --! ============ --
    genPDIfifo: entity work.fifo(structure)
    generic map (
        G_W         => G_PWIDTH,
        G_LOG2DEPTH => G_LOG2_FIFODEPTH)
    port map (
        clk     =>  io_clk,
        rst     =>  rst,
        write   =>  pdi_write,
        read    =>  pdi_read_selected,
        din     =>  pdi_ext,
        dout    =>  pdi,
        full    =>  pdi_full,
        empty   =>  pdi_empty);
    pdi_read_selected   <= '0' when stall_pdi_empty = '1' else pdi_ready;
    pdi_empty_selected  <= '1' when stall_pdi_empty = '1' else pdi_empty;       --! '1' when emptied
    pdi_valid           <= not pdi_empty_selected;
    pdi_delayed         <= pdi after 1/4*clk_period;                            --! Delay to simulate real HW


    genSDIfifo: entity work.fifo(structure)
    generic map (
        G_W         => G_SWIDTH,
        G_LOG2DEPTH => G_LOG2_FIFODEPTH)
    port map (
        clk     =>  io_clk,
        rst     =>  rst,
        write   =>  sdi_write,
        read    =>  sdi_read_selected,
        din     =>  sdi_ext,
        dout    =>  sdi,
        full    =>  sdi_full,
        empty   =>  sdi_empty);
    sdi_read_selected   <= '0' when stall_sdi_empty = '1' else sdi_ready;
    sdi_empty_selected  <= '1' when stall_sdi_empty = '1' else sdi_empty;     -- '1' when emptied
    sdi_valid           <= not sdi_empty_selected;
    sdi_delayed         <= sdi after 1/4*clk_period;    --! Delay to simulate real HW

    genDOfifo: entity work.fifo(structure)
    generic map (
        G_W         => G_PWIDTH,
        G_LOG2DEPTH => G_LOG2_FIFODEPTH)
    port map (
        clk     =>  io_clk,
        rst     =>  rst,
        write   =>  do_write_selected,
        read    =>  do_read,
        din     =>  do,
        dout    =>  do_ext,
        full    =>  do_full,
        empty   =>  do_empty
    );
    do_write_selected   <= '0' when stall_do_full = '1' else do_valid;
    do_full_selected    <= '1' when stall_do_full = '1' else do_full; -- '1' when fulled
    do_ready            <= not do_full_selected;

    uut:  entity work.AEAD(structure)
    generic map  (
        G_PWIDTH    => G_PWIDTH,
        G_SWIDTH    => G_SWIDTH
    )
    port map (
        rst         => rst,
        clk         => clk,
        pdi         => pdi_delayed,
        pdi_ready   => pdi_ready,
        pdi_valid   => pdi_valid,
        sdi         => sdi_delayed,
        sdi_ready   => sdi_ready,
        sdi_valid   => sdi_valid,
        do          => do,
        do_valid    => do_valid,
        do_ready    => do_ready
    );

    --! =================== --
    --! END OF PORT MAPPING --
    --! =================== --


    --! ===========================================================================
    --! ==================== DATA POPULATION FOR PUBLIC DATA ======================
    tb_read_pdi : process
        variable    line_data              : line;
        variable    word_block             : std_logic_vector(G_PWIDTH-1 downto 0) := (others=>'0');
        variable    read_result            : boolean;
        variable    loop_enable            : std_logic   := '1';
        variable    temp_read              : string(1 to 6);
        variable    valid_line             : boolean     := True;
    begin

        rst <= '1';               wait for 5*clk_period;
        rst <= '0';               wait for clk_period;

        --! read header
        while ( not endfile (pdi_file)) and ( loop_enable = '1' ) loop
            if endfile (pdi_file) then
                loop_enable := '0';
            end if;

            readline(pdi_file, line_data);
            read(line_data, temp_read, read_result);
            if (temp_read = cons_ins) then
                loop_enable := '0';
            end if;
        end loop;

        --! do operations in the falling edge of the io_clk
        wait for io_clk_period/2;

        while not endfile ( pdi_file ) loop
            --! if the fifo is full, wait ...
            pdi_write <= '1';
            if ( pdi_full = '1' ) then
                pdi_write <= '0';
                wait until  pdi_full <= '0';
                wait for    io_clk_period/2; --! write in the rising edge
                pdi_write <= '1';
            end if;

            hread( line_data, word_block, read_result );
            while (((read_result = False) or (valid_line = False)) and (not endfile( pdi_file ))) loop
                readline(pdi_file, line_data);
                read(line_data, temp_read, read_result);        --! read line header
                if ( temp_read = cons_ins or temp_read = cons_hdr or temp_read = cons_dat)
                then
                    valid_line := True;
                    pdi_write  <= '1';
                else
                    valid_line := False;
                    pdi_write  <= '0';
                end if;
                hread( line_data, word_block, read_result );    --! read data
            end loop;
            pdi_ext <= word_block;
               wait for io_clk_period;
        end loop;
        pdi_write <= '0';
        wait;
    end process;
    --! ======================================================================
    --! ==================== DATA POPULATION FOR SECRET DATA =================
    tb_read_sdi : process
        variable    line_data              : line;
        variable    word_block             : std_logic_vector(G_SWIDTH-1 downto 0) := (others=>'0');
        variable    read_result            : boolean;
        variable    loop_enable            : std_logic := '1';
        variable    temp_read              : string(1 to 6);
        variable    valid_line             : boolean := True;
    begin

        rst <= '1';               wait for 5*clk_period;
        rst <= '0';               wait for clk_period;

        --! read header
        while (not endfile (sdi_file)) and (loop_enable = '1') loop
            if endfile (sdi_file) then
                loop_enable := '0';
            end if;

            readline(sdi_file, line_data);
            read(line_data, temp_read, read_result);
            if (temp_read = cons_ins) then
                loop_enable := '0';
            end if;
        end loop;

        --! do operations in the falling edge of the io_clk
        wait for io_clk_period/2;

        while not endfile ( sdi_file ) loop
            --! if the fifo is full, wait ...
            sdi_write <= '1';
            if ( sdi_full = '1' ) then
                sdi_write <= '0';
                wait until  sdi_full <= '0';
                wait for    io_clk_period/2; --! write in the rising edge
                sdi_write <= '1';
            end if;

            hread(line_data, word_block, read_result);
            while (((read_result = False) or (valid_line = False)) and (not endfile( sdi_file ))) loop
                readline(sdi_file, line_data);
                read(line_data, temp_read, read_result);        --! read line header
                if ( temp_read = cons_ins or temp_read = cons_hdr or temp_read = cons_dat)
                then
                    valid_line := True;
                    sdi_write  <= '1';
                else
                    valid_line := False;
                    sdi_write  <= '0';
                end if;
                hread( line_data, word_block, read_result );    --! read data
            end loop;
            sdi_ext <= word_block;
            wait for io_clk_period;
        end loop;
        sdi_write <= '0';
        wait;
    end process;
    --! ===========================================================


    --! ===========================================================
    --! =================== DATA VERIFICATION =====================
    tb_verifydata : process
        variable line_no                : integer := 0;
        variable line_data              : line;
        variable logMsg                 : line;
        variable word_block             : std_logic_vector(G_PWIDTH-1 downto 0) := (others=>'0');
        variable read_result            : boolean;
        variable read_result2           : boolean;
        variable loop_enable            : std_logic := '1';
        variable temp_read              : string(1 to 6);
        variable valid_line             : boolean := True;
        variable word_count             : integer := 1;
        variable message_count          : integer := 0;
        variable word_pass              : integer := 1;
        variable instr                  : boolean := False;
        variable next_instr             : boolean := False;
        variable force_exit             : boolean := False;
        variable msgid                  : integer;
        variable keyid                  : integer ;
        variable isEncrypt              : boolean := False;
        variable opcode                 : std_logic_vector(3 downto 0);
    begin
        wait for 6*clk_period;

        while (not endfile (do_file) and valid_line and (not force_exit)) loop
            --! Keep reading new line until a valid line is found
            hread( line_data, word_block, read_result );
            while ((read_result = False or valid_line = False or next_instr = True)
                    and (not endfile(do_file)))
            loop
                readline(do_file, line_data);
                line_no := line_no + 1;
                read(line_data, temp_read, read_result);        --! read line header
                if (temp_read = cons_ins
                    or temp_read = cons_hdr
                    or temp_read = cons_dat)
                then
                    valid_line := True;
                    word_count := 1;
                    if (temp_read = cons_ins) then
                        instr       := True;
                        next_instr  := False;
                    end if;
                else
                    valid_line := False;
                end if;
                if (temp_read = cons_eof) then
                    force_exit := True;
                end if;
                hread(line_data, word_block, read_result);    --! read data
                if (instr = True) then
                    instr := False;
                    msgid  := to_integer(unsigned(word_block(G_PWIDTH- 0-1 downto G_PWIDTH- 8)));
                    keyid  := to_integer(unsigned(word_block(G_PWIDTH-16-1 downto G_PWIDTH-24)));
                    opcode := word_block(G_PWIDTH-12-1 downto G_PWIDTH-16);
                    isEncrypt := False;
                    if ((opcode = OP_AE_DEC or opcode = OP_DEC)
                            or (opcode = OP_AE_PASS or opcode = OP_AE_FAIL))
                    then
                        write(logMsg, string'("[Log] == Verifying msg ID #") & integer'image(msgid)
                            & string'(" with key ID #") & integer'image(keyid));
                        if (opcode = OP_AE_DEC or opcode = OP_DEC) then
                            isEncrypt := True;
                            write(logMsg, string'(" for ENC"));
                        else
                            write(logMsg, string'(" for DEC"));
                        end if;
                        writeline(log_file,logMsg);
                    end if;

                    report "---------Started verifying message number "
                        & integer'image(msgid) & " at " & time'image(now) severity error;
                end if;
            end loop;

            --! if the core is slow in outputting the digested message, wait ...
            if ( valid_line ) then
                do_read <= '1';
                if ( do_empty = '1') then
                    do_read <= '0';
                    wait until do_empty = '0';
                    wait for io_clk_period/2;
                    do_read <= '1';
                end if;

                wait for io_clk_period; -- wait a cycle for data to come out
                word_pass := 1;
                for i in G_PWIDTH-1 downto 0 loop
                    if do_ext(i) /= word_block(i) and word_block(i) /= 'X' then
                        word_pass := 0;
                    end if;
                end loop;
                if word_pass = 0 then
                    simulation_fails <= '1';
                    write(logMsg, string'("[Log] Msg ID #") & integer'image(msgid)
                        & string'(" fails at line #") & integer'image(line_no)
                        & string'(" word #") & integer'image(word_count));
                    writeline(log_file,logMsg);
                    write(logMsg, string'("[Log]     Expected: ") & to_hstring(word_block)
                        & string'(" Received: ") & to_hstring(do_ext));
                    writeline(log_file,logMsg);

                    --! Stop the simulation right away when an error is detected
                    report "---------Data line #"  & integer'image(line_no)
                        & " Word #" & integer'image(word_count)
                        & " at " & time'image(now) & " FAILS T_T --------" severity error;
                    report "Expected: " & to_hstring(word_block)
                        & " Actual: " & to_hstring(do_ext) severity error;
                    write(result_file, "fail");
                    if (G_STOP_AT_FAULT = True) then
                        force_exit := True;
                    else
                        if isEncrypt = False then
                            next_instr := True;
                            report "---------Skip to a next instruction"
                                & " at " & time'image(now) severity error;
                            write(logMsg, string'("[Log]     ...skips to next message ID"));
                            writeline(log_file, logMsg);
                        end if;
                    end if;
                end if;
                word_count := word_count + 1;
            end if;
        end loop;

        do_read <= '0';
        wait for io_clk_period;

        if (simulation_fails = '1') then
            report "FAIL (1): SIMULATION FINISHED || Input/Output files :: T_T"
                & G_FNAME_PDI & "/" & G_FNAME_SDI & "/" & G_FNAME_DO severity error;
            write(result_file, "1");
        else
            report "PASS (0): SIMULATION FINISHED || Input/Output files :: ^0^"
                & G_FNAME_PDI & "/" & G_FNAME_SDI & "/" & G_FNAME_DO severity error;
            write(result_file, "0");
        end if;
        write(logMsg, string'("[Log] Done"));
        writeline(log_file,logMsg);
        stop_clock <= True;
        wait;
    end process;
    --! ===========================================================


    --! ===========================================================
    --! =================== Test MODE =====================
    genInputStall : process
    begin
        if G_TEST_MODE = 1 or G_TEST_MODE = 2 then
            wait until rising_edge( pdi_ready );
            wait for io_clk_period;
            stall_pdi_empty <= '1';
            stall_sdi_empty <= '1';
            wait for io_clk_period*G_TEST_ISTALL;
            stall_pdi_empty <= '0';
            stall_sdi_empty <= '0';
        else
            wait;
        end if;
    end process;
    genOutputStall : process
    begin
        if G_TEST_MODE = 1 or G_TEST_MODE = 3 then
            wait until rising_edge( do_valid );
            wait for io_clk_period;
            stall_do_full <= '1';
            wait for io_clk_period*G_TEST_OSTALL;
            stall_do_full <= '0';
        else
            wait;
        end if;
    end process;
end;
