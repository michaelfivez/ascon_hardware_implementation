-------------------------------------------------------------------------------
--! @project    Unrolled (factor 2) hardware implementation of Asconv128128
--! @author     Michael Fivez
--! @license    This project is released under the GNU Public License.
--!             The license and distribution terms for this file may be
--!             found in the file LICENSE in this distribution or at
--!             http://www.gnu.org/licenses/gpl-3.0.txt
--! @note       This is an hardware implementation made for my graduation thesis
--!             at the KULeuven, in the COSIC department (year 2015-2016)
--!             The thesis is titled 'Energy efficient hardware implementations of CAESAR submissions',
--!             and can be found on the COSIC website (www.esat.kuleuven.be/cosic/publications)
-------------------------------------------------------------------------------

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity FullDiffusionLayer is
	port(		
		X0In : in std_logic_vector(63 downto 0);
		X1In : in std_logic_vector(63 downto 0);
		X2In : in std_logic_vector(63 downto 0);
		X3In : in std_logic_vector(63 downto 0);
		X4In : in std_logic_vector(63 downto 0);
		X0Out : out std_logic_vector(63 downto 0);
		X1Out : out std_logic_vector(63 downto 0);
		X2Out : out std_logic_vector(63 downto 0);
		X3Out : out std_logic_vector(63 downto 0);
		X4Out : out std_logic_vector(63 downto 0));
end entity FullDiffusionLayer;

architecture structural of FullDiffusionLayer is
begin
	Diff0: entity work.DiffusionLayer 
		generic map(SHIFT1 => 19,SHIFT2 => 28)
		port map(X0In,X0Out);
	Diff1: entity work.DiffusionLayer 
		generic map(SHIFT1 => 61,SHIFT2 => 39)
		port map(X1In,X1Out);
	Diff2: entity work.DiffusionLayer 
		generic map(SHIFT1 => 1,SHIFT2 => 6)
		port map(X2In,X2Out);
	Diff3: entity work.DiffusionLayer 
		generic map(SHIFT1 => 10,SHIFT2 => 17)
		port map(X3In,X3Out);
	Diff4: entity work.DiffusionLayer 
		generic map(SHIFT1 => 7,SHIFT2 => 41)
		port map(X4In,X4Out);
end architecture structural;
