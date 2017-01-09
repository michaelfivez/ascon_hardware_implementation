-------------------------------------------------------------------------------
--! @project    Unrolled (factor 4) hardware implementation of Asconv128128
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

entity OutputGenerator is
	port(
		In0 : in std_logic_vector(63 downto 0);
		In1 : in std_logic_vector(63 downto 0);
		DataIn : in std_logic_vector(127 downto 0);
		Size : in std_logic_vector(3 downto 0);
		Activate : in std_logic;
		Out0 : out std_logic_vector(63 downto 0);
		Out1 : out std_logic_vector(63 downto 0);
		DataOut : out std_logic_vector(127 downto 0));
end entity OutputGenerator;

architecture structural of OutputGenerator is
	constant ALLZERO : std_logic_vector(127 downto 0) := (others => '0');
	signal Temp0,Temp1,Temp2 : std_logic_vector(127 downto 0);
begin
	Gen: process(In0,In1,DataIn,Size,Activate,Temp0,Temp1,Temp2) is
		-- Truncator0&1
		procedure doTruncate0 (			-- Truncate block 0 and 1 together
			signal Input : in std_logic_vector(127 downto 0);
			signal Size : in std_logic_vector(3 downto 0);
			signal Activate : in std_logic;
			signal Output : out std_logic_vector(127 downto 0)) is
			variable ActSize : std_logic_vector(4 downto 0);
		begin
			ActSize(4) := Activate;
			ActSize(3 downto 0) := Size;
			-- if inactive it lets everything trough, if active it lets the first blocksize bits trough
			logic: case ActSize is
				when "10001" => 
					Output(127 downto 120) <= Input(127 downto 120);
					Output(119) <= '1';
					Output(118 downto 0) <= ALLZERO(118 downto 0);
				when "10010" => 
					Output(127 downto 112) <= Input(127 downto 112);
					Output(111) <= '1';
					Output(110 downto 0) <= ALLZERO(110 downto 0);
				when "10011" => 
					Output(127 downto 104) <= Input(127 downto 104);
					Output(103) <= '1';
					Output(102 downto 0) <= ALLZERO(102 downto 0);
				when "10100" => 
					Output(127 downto 96) <= Input(127 downto 96);
					Output(95) <= '1';
					Output(94 downto 0) <= ALLZERO(94 downto 0);
				when "10101" => 
					Output(127 downto 88) <= Input(127 downto 88);
					Output(87) <= '1';
					Output(86 downto 0) <= ALLZERO(86 downto 0);
				when "10110" => 
					Output(127 downto 80) <= Input(127 downto 80);
					Output(79) <= '1';
					Output(78 downto 0) <= ALLZERO(78 downto 0);
				when "10111" => 
					Output(127 downto 72) <= Input(127 downto 72);
					Output(71) <= '1';
					Output(70 downto 0) <= ALLZERO(70 downto 0);
				when "11000" => 
					Output(127 downto 64) <= Input(127 downto 64);
					Output(63) <= '1';
					Output(62 downto 0) <= ALLZERO(62 downto 0);
				when "11001" => 
					Output(127 downto 56) <= Input(127 downto 56);
					Output(55) <= '1';
					Output(54 downto 0) <= ALLZERO(54 downto 0);
				when "11010" => 
					Output(127 downto 48) <= Input(127 downto 48);
					Output(47) <= '1';
					Output(46 downto 0) <= ALLZERO(46 downto 0);
				when "11011" => 
					Output(127 downto 40) <= Input(127 downto 40);
					Output(39) <= '1';
					Output(38 downto 0) <= ALLZERO(38 downto 0);
				when "11100" => 
					Output(127 downto 32) <= Input(127 downto 32);
					Output(31) <= '1';
					Output(30 downto 0) <= ALLZERO(30 downto 0);
				when "11101" => 
					Output(127 downto 24) <= Input(127 downto 24);
					Output(23) <= '1';
					Output(22 downto 0) <= ALLZERO(22 downto 0);
				when "11110" => 
					Output(127 downto 16) <= Input(127 downto 16);
					Output(15) <= '1';
					Output(14 downto 0) <= ALLZERO(14 downto 0);
				when "11111" => 
					Output(127 downto 8) <= Input(127 downto 8);
					Output(7) <= '1';
					Output(6 downto 0) <= ALLZERO(6 downto 0);
				when others =>			-- deactivate or blocksize max or invalid input (cas 0xxxx or 10000)
					Output <= Input;
			end case logic;
		end procedure doTruncate0;

		-- Truncator2
		procedure doTruncate2 (			-- Truncate block 0 and 1 together
			signal Input : in std_logic_vector(127 downto 0);
			signal Size : in std_logic_vector(3 downto 0);
			signal Activate : in std_logic;
			signal Output : out std_logic_vector(127 downto 0)) is
			variable ActSize : std_logic_vector(4 downto 0);
		begin
			ActSize(4) := Activate;
			ActSize(3 downto 0) := Size;
			-- if inactive it lets everything trough, if active it blocks the first blocksize bits
			logic: case ActSize is
				when "10000" =>
					Output <= ALLZERO;
				when "10001" => 
					Output(127 downto 120) <= ALLZERO(127 downto 120);
					Output(119 downto 0) <= Input(119 downto 0);
				when "10010" => 
					Output(127 downto 112) <= ALLZERO(127 downto 112);
					Output(111 downto 0) <= Input(111 downto 0);
				when "10011" => 
					Output(127 downto 104) <= ALLZERO(127 downto 104);
					Output(103 downto 0) <= Input(103 downto 0);
				when "10100" => 
					Output(127 downto 96) <= ALLZERO(127 downto 96);
					Output(95 downto 0) <= Input(95 downto 0);
				when "10101" => 
					Output(127 downto 88) <= ALLZERO(127 downto 88);
					Output(87 downto 0) <= Input(87 downto 0);
				when "10110" => 
					Output(127 downto 80) <= ALLZERO(127 downto 80);
					Output(79 downto 0) <= Input(79 downto 0);
				when "10111" => 
					Output(127 downto 72) <= ALLZERO(127 downto 72);
					Output(71 downto 0) <= Input(71 downto 0);
				when "11000" => 
					Output(127 downto 64) <= ALLZERO(127 downto 64);
					Output(63 downto 0) <= Input(63 downto 0);
				when "11001" => 
					Output(127 downto 56) <= ALLZERO(127 downto 56);
					Output(55 downto 0) <= Input(55 downto 0);
				when "11010" => 
					Output(127 downto 48) <= ALLZERO(127 downto 48);
					Output(47 downto 0) <= Input(47 downto 0);
				when "11011" => 
					Output(127 downto 40) <= ALLZERO(127 downto 40);
					Output(39 downto 0) <= Input(39 downto 0);
				when "11100" => 
					Output(127 downto 32) <= ALLZERO(127 downto 32);
					Output(31 downto 0) <= Input(31 downto 0);
				when "11101" => 
					Output(127 downto 24) <= ALLZERO(127 downto 24);
					Output(23 downto 0) <= Input(23 downto 0);
				when "11110" => 
					Output(127 downto 16) <= ALLZERO(127 downto 16);
					Output(15 downto 0) <= Input(15 downto 0);
				when "11111" => 
					Output(127 downto 8) <= ALLZERO(127 downto 8);
					Output(7 downto 0) <= Input(7 downto 0);
				when others =>			-- deactivate or blocksize max or invalid input (cas 0xxxx or 10000)
					Output <= Input;
			end case logic;
		end procedure doTruncate2;
	begin
		-- DataOut
		DataOut(127 downto 64) <= In0 xor DataIn(127 downto 64);
		DataOut(63 downto 0) <= In1 xor DataIn(63 downto 0);
		-- Stateupdate
		doTruncate0(DataIn,Size,Activate,Temp0);
		Temp1(127 downto 64) <= In0;
		Temp1(63 downto 0) <= In1;		
		doTruncate2(Temp1,Size,Activate,Temp2);
		Out0 <= Temp0(127 downto 64) xor Temp2(127 downto 64);
		Out1 <= Temp0(63 downto 0) xor Temp2(63 downto 0);
	end process Gen;
end architecture structural;
