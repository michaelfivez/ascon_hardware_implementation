-------------------------------------------------------------------------------
--! @file       aux_fifo.vhd
--! @brief      Auxiliary FIFO. A custom FIFO used for GMU CAESAR project.
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
use ieee.numeric_std.all;

entity aux_fifo is
    generic (
        G_W             : integer := 32;
        G_LOG2DEPTH     : integer := 6
    );
    port (
        clk             : in  std_logic;
        rst             : in  std_logic;
        fifo_din        : in  std_logic_vector(G_W-1 downto 0);
        fifo_dout       : out std_logic_vector(G_W-1 downto 0);
        fifo_ctrl_in    : in  std_logic_vector(3 downto 0);
        fifo_ctrl_out   : out std_logic_vector(2 downto 0)
    );
end entity aux_fifo;

architecture structure of aux_fifo is
    signal readpointer  	     : std_logic_vector(G_LOG2DEPTH                        -1 downto 0);
    signal writepointer 	     : std_logic_vector(G_LOG2DEPTH                        -1 downto 0);
    signal save_writepointer 	 : std_logic_vector(G_LOG2DEPTH                        -1 downto 0);
   	signal bytecounter  	     : std_logic_vector(G_LOG2DEPTH                           downto 0);
    signal last_bytecounter  	 : std_logic_vector(G_LOG2DEPTH                           downto 0);   --! Byte counter of unread data
    signal last_bytecounter_in   : std_logic_vector(G_LOG2DEPTH                           downto 0);   --! Byte counter of unread data

    signal fifo_save_state       : std_logic;
    signal fifo_restore_state    : std_logic;
    signal fifo_write            : std_logic;
    signal fifo_read             : std_logic;
    signal fifo_unread_avail     : std_logic;
    signal fifo_empty            : std_logic;
    signal fifo_full             : std_logic;
    
    type 	t_mem is array (0 to 2**G_LOG2DEPTH-1) of std_logic_vector(G_W-1 downto 0);
    signal 	memory 		        : t_mem;
begin
    fifo_ctrl_out       <= fifo_full & fifo_empty & fifo_unread_avail;
    fifo_save_state     <= fifo_ctrl_in (0);
    fifo_restore_state  <= fifo_ctrl_in (1);
    fifo_write          <= fifo_ctrl_in (2);
    fifo_read           <= fifo_ctrl_in (3);

    uDPRAM:
    process(clk)
    begin
        if (rising_edge(clk)) then
            if (fifo_write = '1') then
                memory(to_integer(unsigned(writepointer))) <= fifo_din;
            end if;
            if (fifo_read = '1') then
                fifo_dout <= memory(to_integer(unsigned(readpointer)));
            end if;
        end if;
    end process;

    p_fifo_ptr:
    process(clk)
    begin
        if rising_edge( clk ) then
            if rst = '1' then
                readpointer         <= (others => '0');
                writepointer        <= (others => '0');
                bytecounter         <= (others => '0');  --differences (write pointer - read pointer)
                save_writepointer   <= (others => '0');
            else
                if (fifo_save_state = '1') then
                    save_writepointer <= std_logic_vector(unsigned(readpointer) + unsigned(bytecounter(G_LOG2DEPTH-1 downto 0)));
                    last_bytecounter  <= bytecounter;
                end if;

                if (fifo_write = '1' and fifo_read = '1') then
                    writepointer <= std_logic_vector(unsigned(writepointer) + 1);
                    readpointer  <= std_logic_vector(unsigned(readpointer) + 1);
                    if (unsigned(last_bytecounter) /= 0) then
                        last_bytecounter <= std_logic_vector(unsigned(last_bytecounter_in) - 1);
                    end if;
                elsif (fifo_write = '1' and fifo_read = '0') then
                    writepointer <= std_logic_vector(unsigned(writepointer) + 1);
                    bytecounter  <= std_logic_vector(unsigned(bytecounter) + 1);
                elsif (fifo_write = '0' and fifo_read = '1') then
                    readpointer  <= std_logic_vector(unsigned(readpointer) + 1);
                    if (fifo_restore_state = '1') then
                        writepointer <= save_writepointer;
                        bytecounter  <= '0' & std_logic_vector(unsigned(save_writepointer) - (unsigned(readpointer) - 1));
                    else
                        bytecounter <= std_logic_vector(unsigned(bytecounter) - 1);
                    end if;
                    if (unsigned(last_bytecounter) /= 0) then
                        last_bytecounter <= std_logic_vector(unsigned(last_bytecounter_in) - 1);
                    end if;
                elsif (fifo_restore_state = '1') then
                    writepointer <= save_writepointer;
                    bytecounter  <= '0' & std_logic_vector(unsigned(save_writepointer) - unsigned(readpointer));
                end if;
            end if;
        end if;
    end process;

    last_bytecounter_in <= bytecounter when fifo_save_state = '1' else last_bytecounter;
    fifo_unread_avail <= '1' when unsigned(last_bytecounter) > 0 else '0';
    -- fifo_empty      <= '1' when (unsigned(bytecounter) = 0 or (fifo_read = '1' and unsigned(bytecounter) = 1)) else  '0';
    fifo_empty      <= '1' when (unsigned(bytecounter) = 0) else  '0';
    fifo_full       <= '1' when (unsigned(bytecounter) >= 2**G_LOG2DEPTH-1) else '0';
end structure;