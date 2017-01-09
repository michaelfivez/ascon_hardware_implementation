-------------------------------------------------------------------------------
--! @file       regn.vhd
--! @brief      Register with init value
--! @project    CAESAR Candidate Evaluation
--! @author     CERG @ GMU
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

entity regn is
	generic ( 
		N : integer := 32;
		init : std_logic_vector
	);
	port ( 	  
	    clk 	: in std_logic;
		rst 	: in std_logic;
	    en 		: in std_logic; 
		input  	: in std_logic_vector(N-1 downto 0);
        output 	: out std_logic_vector(N-1 downto 0)
	);
end regn;

architecture struct of regn is
--signal reg : std_logic_vector(N-1 downto 0);
begin	
	gen : process( clk )
	begin
		if rising_edge( clk ) then
			if ( rst = '1' ) then
				output <= init;
			elsif ( en = '1' ) then
				output<= input;
			end if;
		end if;
	end process;
	--output <= reg;  
end struct;