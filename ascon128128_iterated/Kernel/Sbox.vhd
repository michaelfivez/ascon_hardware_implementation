-------------------------------------------------------------------------------
--! @project    Iterate hardware implementation of Asconv128128
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

entity Sbox is
	port(
		X0In : in std_logic_vector(63 downto 0);
		X1In : in std_logic_vector(63 downto 0);
		X2In : in std_logic_vector(63 downto 0);
		X3In : in std_logic_vector(63 downto 0);
		X4In : in std_logic_vector(63 downto 0);
		RoundNr : in std_logic_vector(3 downto 0);
		X0Out : out std_logic_vector(63 downto 0);
		X1Out : out std_logic_vector(63 downto 0);
		X2Out : out std_logic_vector(63 downto 0);
		X3Out : out std_logic_vector(63 downto 0);
		X4Out : out std_logic_vector(63 downto 0));
end entity Sbox;

architecture structural of Sbox is
begin
	Sbox: process(X0In,X1In,X2In,X3In,X4In,RoundNr) is			
		-- Procedure for 5-bit Sbox
		procedure doSboxPart (
			variable SboxPartIn : in std_logic_vector(4 downto 0);
			variable SboxPartOut : out std_logic_vector(4 downto 0)) is
			-- Temp variable
			variable SboxPartTemp : std_logic_vector(17 downto 0);
		begin
			-- Sbox Interconnections
			SboxPartTemp(0) := SboxPartIn(0) xor SboxPartIn(4);
			SboxPartTemp(1) := SboxPartIn(2) xor SboxPartIn(1);
			SboxPartTemp(2) := SboxPartIn(4) xor SboxPartIn(3);
			SboxPartTemp(3) := not SboxPartTemp(0);
			SboxPartTemp(4) := not SboxPartIn(1);
			SboxPartTemp(5) := not SboxPartTemp(1);
			SboxPartTemp(6) := not SboxPartIn(3);
			SboxPartTemp(7) := not SboxPartTemp(2);
			SboxPartTemp(8) := SboxPartIn(1) and SboxPartTemp(3);
			SboxPartTemp(9) := SboxPartTemp(1) and SboxPartTemp(4);
			SboxPartTemp(10) := SboxPartIn(3) and SboxPartTemp(5);
			SboxPartTemp(11) := SboxPartTemp(2) and SboxPartTemp(6);
			SboxPartTemp(12) := SboxPartTemp(0) and SboxPartTemp(7);
			SboxPartTemp(13) := SboxPartTemp(0) xor SboxPartTemp(9);
			SboxPartTemp(14) := SboxPartIn(1) xor SboxPartTemp(10);
			SboxPartTemp(15) := SboxPartTemp(1) xor SboxPartTemp(11);
			SboxPartTemp(16) := SboxPartIn(3) xor SboxPartTemp(12);
			SboxPartTemp(17) := SboxPartTemp(2) xor SboxPartTemp(8);
			SboxPartOut(0) := SboxPartTemp(13) xor SboxPartTemp(17);
			SboxPartOut(1) := SboxPartTemp(13) xor SboxPartTemp(14);
			SboxPartOut(2) := not SboxPartTemp(15);
			SboxPartOut(3) := SboxPartTemp(15) xor SboxPartTemp(16);
			SboxPartOut(4) := SboxPartTemp(17);
		end procedure doSboxPart;
		variable X2TempIn : std_logic_vector(63 downto 0);
		variable TempIn,TempOut : std_logic_vector(4 downto 0);
	begin
		-- Xor with round constants
		X2TempIn(3 downto 0) := X2In(3 downto 0) xor RoundNr;
		X2TempIn(7 downto 4) := X2In(7 downto 4) xnor RoundNr;
		X2TempIn(63 downto 8) := X2In(63 downto 8);
		-- Apply 5-bit Sbox 64 times
		for i in X0In'range loop
			TempIn(0) := X0In(i);
			TempIn(1) := X1In(i);
			TempIn(2) := X2TempIn(i);
			TempIn(3) := X3In(i);
			TempIn(4) := X4In(i);
			doSboxPart(TempIn,TempOut);
			X0Out(i) <= TempOut(0);
			X1Out(i) <= TempOut(1);
			X2Out(i) <= TempOut(2);
			X3Out(i) <= TempOut(3);
			X4Out(i) <= TempOut(4);
		end loop;
	end process Sbox;
end architecture structural;
