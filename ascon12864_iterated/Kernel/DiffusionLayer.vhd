-------------------------------------------------------------------------------
--! @project    Iterated hardware implementation of Asconv12864
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

entity DiffusionLayer is
	generic(	SHIFT1 : integer range 0 to 63;
			SHIFT2 : integer range 0 to 63);
		
	port(		Input : in std_logic_vector(63 downto 0);
			Output : out std_logic_vector(63 downto 0));
end entity DiffusionLayer;

architecture structural of DiffusionLayer is
begin
	DiffLayer: process(Input) is			
		variable Temp0,Temp1 : std_logic_vector(63 downto 0);
	begin
		Temp0(63 downto 64-SHIFT1) := Input(SHIFT1-1 downto 0);
		Temp0(63-SHIFT1 downto 0) := Input(63 downto SHIFT1);
		Temp1(63 downto 64-SHIFT2) := Input(SHIFT2-1 downto 0);
		Temp1(63-SHIFT2 downto 0) := Input(63 downto SHIFT2);
		Output <= Temp0 xor Temp1 xor Input;
	end process DiffLayer;
end architecture structural;
