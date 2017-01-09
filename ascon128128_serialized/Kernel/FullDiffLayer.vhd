-------------------------------------------------------------------------------
--! @project    Serialized hardware implementation of Asconv128128
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
		Diff1In : in std_logic_vector(63 downto 0);
		Diff2In : in std_logic_vector(63 downto 0);
		Diff3In : in std_logic_vector(63 downto 0);
		DiffOut : out std_logic_vector(63 downto 0));
end entity FullDiffusionLayer;

architecture structural of FullDiffusionLayer is
begin
	DiffOut <= Diff1In xor Diff2In xor Diff3In;
end architecture structural;
