-------------------------------------------------------------------------------
--! @file       fifo.vhd
--! @brief      standard FIFO
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

entity fifo is
    generic (	
        G_LOG2DEPTH 		: integer := 9;         --! LOG(2) of depth
        G_W 				: integer := 64         --! Width of I/O (bits)
    );
    port (
        clk				    : in  std_logic;
        rst				    : in  std_logic;
        write			    : in  std_logic; 
        read			    : in  std_logic;
        din 			    : in  std_logic_vector(G_W-1 downto 0);
        dout	 		    : out std_logic_vector(G_W-1 downto 0);
        almost_full         : out std_logic;
        almost_empty        : out std_logic;
        full			    : out std_logic; 
        empty 			    : out std_logic
    );
end fifo;

architecture structure of fifo is

	signal readpointer  	: std_logic_vector(G_LOG2DEPTH            -1 downto 0);
	signal writepointer 	: std_logic_vector(G_LOG2DEPTH            -1 downto 0);
	signal bytecounter  	: std_logic_vector(G_LOG2DEPTH               downto 0);
	signal write_s 			: std_logic;
	signal full_s    	    : std_logic;
	signal empty_s   	    : std_logic;

    type 	mem is array (2**G_LOG2DEPTH-1 downto 0) of std_logic_vector(G_W-1 downto 0);
	signal 	memory 		    : mem;
begin		 
	
    p_fifo_ram:
    process(clk)
    begin
        if ( rising_edge(clk) ) then
            if (write_s = '1') then
                memory(to_integer(unsigned(writepointer))) <= din;
            end if;	 
            if (read = '1') then
                dout <= memory(to_integer(unsigned(readpointer)));
            end if;
        end if;
    end process; 
    
    p_fifo_ptr:
	process(clk)
	begin		
		if rising_edge( clk ) then
            if rst = '1' then                
                readpointer  <= (others => '0');
                writepointer <= (others => '0'); 
                bytecounter  <= (others => '0');  --differences (write pointer - read pointer)
            else 
                if ( write = '1' and full_s = '0' and read = '0') then
                    writepointer <= writepointer + 1;
                    bytecounter  <= bytecounter + 1;
                elsif ( read = '1' and empty_s = '0' and write = '0') then
                    readpointer  <= readpointer + 1;
                    bytecounter  <= bytecounter - 1;
                elsif ( read = '1' and empty_s = '0' and write = '1' and full_s = '0') then
                    readpointer <= readpointer + 1;
                    writepointer <= writepointer + 1;
                elsif ( read = '1' and empty_s = '0' and write = '1' and full_s = '1') then	-- cant write
                    readpointer <= readpointer + 1;
                    bytecounter <= bytecounter - 1;
                elsif ( read = '1' and empty_s = '1' and write = '1' and full_s = '0') then -- cant read
                    writepointer <= writepointer + 1;
                    bytecounter <= bytecounter + 1;
                end if;
            end if;
		end if;
	end process;

	empty_s         <= '1' when (bytecounter = 0) else  '0';
	full_s          <= bytecounter(G_LOG2DEPTH);
    almost_full     <= '1' when (bytecounter >= 2**G_LOG2DEPTH-1) else '0';    
	full            <= full_s;
	empty           <= empty_s;
    almost_empty    <= '1' when (bytecounter = 1) else '0';
    

	write_s <= '1' when ( write = '1' and full_s = '0') else '0';

end structure;
